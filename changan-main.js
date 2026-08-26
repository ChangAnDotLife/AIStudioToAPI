/*
 * ChangAnDotLife server-hardening entrypoint.
 *
 * Keeps the upstream application code intact and applies a small set of
 * deployment-focused overrides before starting the server. This minimizes
 * fork drift and makes future upstream syncs easier.
 */

const express = require("express");

// main.js loads dotenv but does not auto-start when required as a module.
const { initializeServer, ProxyServerSystem } = require("./main");
const AuthSwitcher = require("./src/auth/AuthSwitcher");
const ConfigLoader = require("./src/utils/ConfigLoader");
const ConnectionRegistry = require("./src/core/ConnectionRegistry");
const RequestHandler = require("./src/core/RequestHandler");
const MessageQueue = require("./src/utils/MessageQueue");
const StatusRoutes = require("./src/routes/StatusRoutes");

const DEFAULT_AI_STUDIO_APP_URL = "https://ai.studio/apps/cab9ab6c-44f9-4e7a-8972-037f8ae177ab";
const DEFAULT_MAX_REQUEST_BODY_BYTES = 64 * 1024 * 1024;
const INTERNAL_WS_HOST = "127.0.0.1";
const AUTO_STREAM_RETRY_SENTINEL_STATUS = 429;
const SUPPORTED_STREAMING_MODES = new Set(["auto", "fake", "real"]);

const singleAccountRuntime = {
    last429At: null,
    last429Message: null,
};

const streamRuntime = {
    fallbackCount: 0,
    lastFallbackAt: null,
    lastFallbackModel: null,
};

// Request-scoped state used only while STREAMING_MODE=auto requests are active.
// The first Google 403/PERMISSION_DENIED is converted to an internal retry
// sentinel before the existing real-stream handler exposes anything to clients.
const autoStreamRequests = new Map();

if (process.platform !== "win32") {
    // New auth/session files created by this process default to owner-only access.
    process.umask(0o077);
}

function hasConfiguredApiKey() {
    return String(process.env.API_KEYS || "")
        .split(",")
        .some(value => value.trim().length > 0);
}

function getRequestBodyLimit() {
    const raw = process.env.MAX_REQUEST_BODY_BYTES;
    if (!raw) return DEFAULT_MAX_REQUEST_BODY_BYTES;

    const parsed = Number.parseInt(raw, 10);
    if (!Number.isFinite(parsed) || parsed <= 0) {
        throw new Error("MAX_REQUEST_BODY_BYTES must be a positive integer.");
    }
    return parsed;
}

function getAiStudioAppUrl() {
    const raw = String(process.env.AISTUDIO_APP_URL || DEFAULT_AI_STUDIO_APP_URL).trim();
    let url;
    try {
        url = new URL(raw);
    } catch {
        throw new Error("AISTUDIO_APP_URL must be a valid URL.");
    }

    if (url.protocol !== "https:" || url.hostname !== "ai.studio" || !url.pathname.startsWith("/apps/")) {
        throw new Error("AISTUDIO_APP_URL must be an https://ai.studio/apps/... URL.");
    }
    return url.toString();
}

function getRequestedStreamingMode() {
    const mode = String(process.env.STREAMING_MODE || "auto")
        .trim()
        .toLowerCase();
    if (!SUPPORTED_STREAMING_MODES.has(mode)) {
        throw new Error(`STREAMING_MODE must be one of: ${Array.from(SUPPORTED_STREAMING_MODES).join(", ")}.`);
    }
    return mode;
}

function isSingleCanonicalAccount(authSource) {
    const indices = authSource?.getRotationIndices?.();
    return Array.isArray(indices) && indices.length === 1;
}

function isAutoStreamCandidate(handler, proxyRequest) {
    return Boolean(
        handler?.config?.autoStreamFallback === true &&
            proxyRequest &&
            proxyRequest.streaming_mode === "real" &&
            typeof proxyRequest.path === "string" &&
            proxyRequest.path.includes(":streamGenerateContent")
    );
}

function getOrCreateAutoStreamState(handler, proxyRequest) {
    if (!isAutoStreamCandidate(handler, proxyRequest)) {
        return autoStreamRequests.get(proxyRequest?.request_id) || null;
    }

    const requestId = proxyRequest.request_id;
    let state = autoStreamRequests.get(requestId);
    if (!state) {
        const modelMatch = proxyRequest.path.match(/\/models\/([^:/?]+)/);
        state = {
            fallbackApplied: false,
            fallbackPending: false,
            model: modelMatch?.[1] || null,
            nativeResponse: null,
            originalPath: proxyRequest.path,
            permissionDeniedSeen: false,
        };
        autoStreamRequests.set(requestId, state);
    }
    return state;
}

function isPermissionDenied403(message) {
    return Boolean(
        message &&
            message.event_type === "error" &&
            Number(message.status) === 403 &&
            String(message.message || "").includes("PERMISSION_DENIED")
    );
}

// Fail closed in production instead of silently exposing the upstream default key "123456".
const originalLoadConfiguration = ConfigLoader.prototype.loadConfiguration;
ConfigLoader.prototype.loadConfiguration = function loadHardenedConfiguration() {
    if (process.env.NODE_ENV === "production" && !hasConfiguredApiKey()) {
        throw new Error("API_KEYS is required in production; refusing to use the insecure default key.");
    }

    const requestedStreamingMode = getRequestedStreamingMode();
    const config = originalLoadConfiguration.call(this);
    config.maxRequestBodyBytes = getRequestBodyLimit();
    config.aiStudioAppUrl = getAiStudioAppUrl();
    config.requestedStreamingMode = requestedStreamingMode;
    config.autoStreamFallback = requestedStreamingMode === "auto";

    // Upstream RequestHandler understands real/fake. Auto starts on the real path.
    // A request-scoped server-side retry hook below switches only the failed request
    // to the already-supported fake path when Google rejects streamGenerateContent
    // with 403 PERMISSION_DENIED before response headers reach the client.
    config.streamingMode = requestedStreamingMode === "auto" ? "real" : requestedStreamingMode;

    // Auto fallback reuses the existing "immediate status retry" control flow with
    // a request-local synthetic status. Keep 429 available as that internal sentinel.
    if (
        config.autoStreamFallback &&
        !config.immediateSwitchStatusCodes.includes(AUTO_STREAM_RETRY_SENTINEL_STATUS)
    ) {
        config.immediateSwitchStatusCodes.push(AUTO_STREAM_RETRY_SENTINEL_STATUS);
    }

    return config;
};

// In a one-account deployment, request-count rotation only refreshes the same
// browser/account and does not increase Google quota. Keep the context stable.
const originalShouldSwitchByUsage = AuthSwitcher.prototype.shouldSwitchByUsage;
AuthSwitcher.prototype.shouldSwitchByUsage = function shouldSwitchByUsageSingleAccountAware() {
    if (isSingleCanonicalAccount(this.authSource)) {
        if (!this.__singleAccountRotationNoticeLogged && this.config.switchOnUses > 0) {
            this.logger.info(
                `[Hardening] Single-account mode detected; ignoring SWITCH_ON_USES=${this.config.switchOnUses}.`
            );
            this.__singleAccountRotationNoticeLogged = true;
        }
        return false;
    }
    return originalShouldSwitchByUsage.call(this);
};

// A 429 on the only account usually means an upstream rate/quota limit. Restarting
// the same browser cannot create new quota and can make a healthy session less stable.
const originalHandleRequestFailureAndSwitch = AuthSwitcher.prototype.handleRequestFailureAndSwitch;
AuthSwitcher.prototype.handleRequestFailureAndSwitch = async function handleFailureSingleAccountAware(
    errorDetails,
    sendErrorCallback
) {
    const status = Number(errorDetails?.status);
    if (status === 429 && isSingleCanonicalAccount(this.authSource)) {
        singleAccountRuntime.last429At = Date.now();
        singleAccountRuntime.last429Message = String(errorDetails?.message || "Too Many Requests");
        this.failureCount = 0;

        this.logger.warn(
            "[Hardening] Single account received HTTP 429; preserving the current browser context instead of restarting it."
        );
        if (sendErrorCallback) {
            sendErrorCallback("Google rate/quota limit reached on the only configured account.");
        }
        return {
            reason: "single_account_rate_limited",
            success: false,
        };
    }

    return originalHandleRequestFailureAndSwitch.call(this, errorDetails, sendErrorCallback);
};

// Tag each queue with its request ID so the first browser response can be examined
// without modifying the upstream RequestHandler source.
const originalCreateMessageQueue = ConnectionRegistry.prototype.createMessageQueue;
ConnectionRegistry.prototype.createMessageQueue = function createMessageQueueWithAutoStreamMetadata(
    requestId,
    authIndex,
    requestAttemptId = null
) {
    const queue = originalCreateMessageQueue.call(this, requestId, authIndex, requestAttemptId);
    queue.__changanRequestId = requestId;
    queue.__changanDequeueCount = 0;
    return queue;
};

// Only the first message of a real-stream attempt is eligible for fallback. This
// guarantees that a stream which already started is never replayed.
const originalMessageQueueDequeue = MessageQueue.prototype.dequeue;
MessageQueue.prototype.dequeue = async function dequeueWithAutoStreamFallback(...args) {
    const message = await originalMessageQueueDequeue.apply(this, args);
    this.__changanDequeueCount = (this.__changanDequeueCount || 0) + 1;

    if (this.__changanDequeueCount !== 1) {
        return message;
    }

    const state = autoStreamRequests.get(this.__changanRequestId);
    if (!state || state.fallbackApplied || state.fallbackPending || !isPermissionDenied403(message)) {
        return message;
    }

    state.permissionDeniedSeen = true;

    // The upstream real-stream loop already has a safe "cancel old attempt ->
    // create new queue -> resend" path for configured immediate statuses. Convert
    // only this request-local error into the existing 429 control-flow sentinel.
    return {
        ...message,
        __changanAutoStreamFallback: true,
        __changanOriginalStatus: 403,
        status: AUTO_STREAM_RETRY_SENTINEL_STATUS,
    };
};

// Register eligible real-stream attempts before they are sent. When the retry hook
// below marks a request pending, resend the same request on the same account through
// the project's native fake-stream path (generateContent).
const originalForwardRequest = RequestHandler.prototype._forwardRequest;
RequestHandler.prototype._forwardRequest = function forwardRequestWithAutoStreamFallback(
    proxyRequest,
    authIndex = this.currentAuthIndex
) {
    const state = getOrCreateAutoStreamState(this, proxyRequest);

    if (state?.fallbackPending && !state.fallbackApplied) {
        proxyRequest.streaming_mode = "fake";
        if (typeof proxyRequest.path === "string") {
            proxyRequest.path = proxyRequest.path.replace(":streamGenerateContent", ":generateContent");
        }
        if (proxyRequest.query_params && proxyRequest.query_params.alt === "sse") {
            delete proxyRequest.query_params.alt;
        }

        state.fallbackPending = false;
        state.fallbackApplied = true;
        streamRuntime.fallbackCount += 1;
        streamRuntime.lastFallbackAt = Date.now();
        streamRuntime.lastFallbackModel = state.model;

        if (state.nativeResponse) {
            state.nativeResponse.__changanAutoStreamFallback = true;
        }

        this._updateTrackedRequest?.(proxyRequest.request_id, {
            path: proxyRequest.path,
            streamMode: "fake-fallback",
        });

        this.logger.warn(
            `[Hardening] Auto stream fallback active for request #${proxyRequest.request_id}` +
                `${state.model ? ` (model=${state.model})` : ""}: retrying once via generateContent on the same account.`
        );
    }

    return originalForwardRequest.call(this, proxyRequest, authIndex);
};

// Intercept only the synthetic request-local retry sentinel. Do not switch account:
// the fallback must replay on the same authenticated Google session.
const originalPrepareImmediateStatusRetry = RequestHandler.prototype._prepareImmediateStatusRetry;
RequestHandler.prototype._prepareImmediateStatusRetry = async function prepareAutoStreamFallbackRetry(
    errorDetails,
    requestId,
    tracker,
    sourceAuthIndex
) {
    if (errorDetails?.__changanAutoStreamFallback === true) {
        const state = autoStreamRequests.get(requestId);
        if (state && state.permissionDeniedSeen && !state.fallbackApplied) {
            state.fallbackPending = true;
            this.logger.warn(
                `[Hardening] Google rejected real stream with 403 PERMISSION_DENIED for request #${requestId}; ` +
                    "preparing one same-account fake-stream retry before any client response is sent."
            );
            return true;
        }
        return false;
    }

    return originalPrepareImmediateStatusRetry.call(this, errorDetails, requestId, tracker, sourceAuthIndex);
};

// Gemini-native real streaming writes Google SSE directly instead of running through
// a format converter. If auto fallback returned one buffered generateContent JSON
// body, frame that one body as a valid SSE data event.
const originalHandleRealStreamResponse = RequestHandler.prototype._handleRealStreamResponse;
RequestHandler.prototype._handleRealStreamResponse = async function handleGeminiRealStreamWithAutoFallback(
    proxyRequest,
    messageQueue,
    req,
    res
) {
    const state = getOrCreateAutoStreamState(this, proxyRequest);
    if (state) {
        state.nativeResponse = res;
    }

    const originalWrite = res.write;
    res.write = function writeWithAutoStreamFraming(chunk, ...rest) {
        const activeState = autoStreamRequests.get(proxyRequest.request_id);
        if (activeState?.fallbackApplied && !activeState.nativeFallbackChunkWritten) {
            const text = Buffer.isBuffer(chunk) ? chunk.toString("utf8") : String(chunk);
            const trimmed = text.trim();
            if (trimmed && !trimmed.startsWith("data:") && (trimmed.startsWith("{") || trimmed.startsWith("["))) {
                let payload = trimmed;
                try {
                    payload = JSON.stringify(JSON.parse(trimmed));
                } catch {
                    // The upstream fake path already returned a complete body; if it
                    // is not JSON, preserve the body rather than silently dropping it.
                }
                activeState.nativeFallbackChunkWritten = true;
                return originalWrite.call(this, `data: ${payload}\n\n`, ...rest);
            }
        }
        return originalWrite.call(this, chunk, ...rest);
    };

    try {
        return await originalHandleRealStreamResponse.call(this, proxyRequest, messageQueue, req, res);
    } finally {
        res.write = originalWrite;
    }
};

const originalSetResponseHeaders = RequestHandler.prototype._setResponseHeaders;
RequestHandler.prototype._setResponseHeaders = function setHeadersWithAutoStreamFallback(res, headerMessage, req) {
    const result = originalSetResponseHeaders.call(this, res, headerMessage, req);
    if (res.__changanAutoStreamFallback === true) {
        res.removeHeader("content-length");
        res.removeHeader("content-encoding");
        res.removeHeader("transfer-encoding");
        res.status(200);
        res.set({
            "Cache-Control": "no-cache",
            Connection: "keep-alive",
            "Content-Type": "text/event-stream; charset=utf-8",
        });
    }
    return result;
};

// Request-scoped fallback state must not accumulate after requests finish.
const originalFinalizeTrackedRequest = RequestHandler.prototype._finalizeTrackedRequest;
RequestHandler.prototype._finalizeTrackedRequest = function finalizeAndCleanupAutoStreamState(requestId, ...args) {
    try {
        return originalFinalizeTrackedRequest.call(this, requestId, ...args);
    } finally {
        autoStreamRequests.delete(requestId);
    }
};

// Keep the internal browser WebSocket private.
const originalStartWebSocketServer = ProxyServerSystem.prototype._startWebSocketServer;
ProxyServerSystem.prototype._startWebSocketServer = async function startLoopbackWebSocketServer() {
    const publicHost = this.config.host;
    this.config.host = INTERNAL_WS_HOST;
    try {
        return await originalStartWebSocketServer.call(this);
    } finally {
        this.config.host = publicHost;
    }
};

// Make the AI Studio Build App target configurable without changing BrowserManager.
const originalStart = ProxyServerSystem.prototype.start;
ProxyServerSystem.prototype.start = async function startWithConfiguredTarget(...args) {
    this.browserManager.targetUrl = this.config.aiStudioAppUrl || DEFAULT_AI_STUDIO_APP_URL;
    this.logger.info(`[Hardening] AI Studio app target: ${this.browserManager.targetUrl}`);
    this.logger.info(`[Hardening] Internal WebSocket bound to ${INTERNAL_WS_HOST}:${this.config.wsPort}`);
    this.logger.info(`[Hardening] Max request body: ${this.config.maxRequestBodyBytes} bytes`);
    if (this.config.autoStreamFallback) {
        this.logger.info(
            "[Hardening] Streaming mode: auto (real first; 403 PERMISSION_DENIED retries once through the server-side fake-stream path)."
        );
    } else {
        this.logger.info(`[Hardening] Streaming mode: ${this.config.requestedStreamingMode}`);
    }
    return originalStart.apply(this, args);
};

// Put a small guard in front of the upstream Express app. Content-Length requests
// get a deterministic 413 response; chunked requests are also watched and aborted
// if they exceed the configured cap.
const originalCreateExpressApp = ProxyServerSystem.prototype._createExpressApp;
ProxyServerSystem.prototype._createExpressApp = function createHardenedExpressApp() {
    const upstreamApp = originalCreateExpressApp.call(this);
    const wrapper = express();
    const limit = this.config.maxRequestBodyBytes || DEFAULT_MAX_REQUEST_BODY_BYTES;

    wrapper.use((req, res, next) => {
        if (req.method === "GET" || req.method === "HEAD" || req.method === "OPTIONS") {
            return next();
        }

        const contentLength = Number.parseInt(req.headers["content-length"], 10);
        if (Number.isFinite(contentLength) && contentLength > limit) {
            res.setHeader("Connection", "close");
            return res.status(413).json({
                error: {
                    message: `Request body exceeds the configured ${limit}-byte limit.`,
                },
            });
        }

        let received = 0;
        let exceeded = false;
        const onData = chunk => {
            if (exceeded) return;
            received += chunk.length;
            if (received <= limit) return;

            exceeded = true;
            this.logger.warn(`[Hardening] Aborting oversized chunked request: ${req.method} ${req.url}`);
            if (!res.headersSent) {
                res.setHeader("Connection", "close");
                res.status(413).json({
                    error: {
                        message: `Request body exceeds the configured ${limit}-byte limit.`,
                    },
                });
            }
            req.destroy();
        };

        const cleanup = () => req.removeListener("data", onData);
        req.on("data", onData);
        req.once("end", cleanup);
        req.once("close", cleanup);
        return next();
    });

    wrapper.use(upstreamApp);
    return wrapper;
};

// Add a readiness endpoint without changing the upstream /health liveness contract.
const originalSetupRoutes = StatusRoutes.prototype.setupRoutes;
StatusRoutes.prototype.setupRoutes = function setupHardenedRoutes(app, isAuthenticated) {
    app.get("/readyz", (req, res) => {
        const { authSource, browserManager, connectionRegistry, requestHandler } = this.serverSystem;
        const currentAuthIndex = requestHandler.currentAuthIndex;
        const authAvailable = authSource.availableIndices.length > 0;
        const browserConnected = !!browserManager.browser;
        const wsConnected =
            Number.isInteger(currentAuthIndex) &&
            currentAuthIndex >= 0 &&
            !!connectionRegistry.getConnectionByAuth(currentAuthIndex, false);
        const busy = requestHandler.isSystemBusy === true;
        const ready = authAvailable && browserConnected && wsConnected && !busy;
        const singleAccount = isSingleCanonicalAccount(authSource);

        return res.status(ready ? 200 : 503).json({
            authAvailable,
            autoStreamFallback: requestHandler.config?.autoStreamFallback === true,
            autoStreamFallbackCount: streamRuntime.fallbackCount,
            browserConnected,
            busy,
            currentAuthIndex,
            lastAutoStreamFallbackAt: streamRuntime.lastFallbackAt,
            lastAutoStreamFallbackModel: streamRuntime.lastFallbackModel,
            lastSingleAccount429At: singleAccountRuntime.last429At,
            ready,
            singleAccount,
            streamingMode: requestHandler.config?.requestedStreamingMode || requestHandler.config?.streamingMode,
            wsConnected,
        });
    });

    return originalSetupRoutes.call(this, app, isAuthenticated);
};

initializeServer();
