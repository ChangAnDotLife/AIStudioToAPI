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
const BrowserManager = require("./src/core/BrowserManager");
const ConfigLoader = require("./src/utils/ConfigLoader");
const StatusRoutes = require("./src/routes/StatusRoutes");

const DEFAULT_AI_STUDIO_APP_URL = "https://ai.studio/apps/cab9ab6c-44f9-4e7a-8972-037f8ae177ab";
const DEFAULT_MAX_REQUEST_BODY_BYTES = 64 * 1024 * 1024;
const INTERNAL_WS_HOST = "127.0.0.1";
const SUPPORTED_STREAMING_MODES = new Set(["auto", "fake", "real"]);

const singleAccountRuntime = {
    last429At: null,
    last429Message: null,
};

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

    // Upstream RequestHandler understands real/fake. In auto mode it should take
    // the real-stream path first; the browser-side init script below performs a
    // pre-body fallback when Google rejects streamGenerateContent with 403
    // PERMISSION_DENIED.
    config.streamingMode = requestedStreamingMode === "auto" ? "real" : requestedStreamingMode;
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
// Preserve the context, return Google's error to the caller, and let future requests
// probe naturally after the upstream limit resets.
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

// STREAMING_MODE=auto is implemented below the remote Build App by wrapping fetch
// in every browser frame before application code runs. A streamGenerateContent 403
// with PERMISSION_DENIED is retried exactly once as generateContent, before any
// headers/body have been sent through the internal WebSocket. The successful JSON
// response is wrapped as one valid Google SSE event, so the existing upstream real-
// stream adapters continue to work for Gemini/OpenAI/Responses/Anthropic clients.
const originalGetPrivacyProtectionScript = BrowserManager.prototype._getPrivacyProtectionScript;
BrowserManager.prototype._getPrivacyProtectionScript = function getPrivacyScriptWithAutoStreamFallback(...args) {
    const baseScript = originalGetPrivacyProtectionScript.apply(this, args);
    if (this.config?.autoStreamFallback !== true) {
        return baseScript;
    }

    const autoStreamFallbackScript = String.raw`
        ;(() => {
            if (window.__changanAutoStreamFallbackInstalled === true) return;
            window.__changanAutoStreamFallbackInstalled = true;

            const originalFetch = window.fetch.bind(window);

            window.fetch = async function changanAutoStreamFetch(input, init) {
                const inputUrl =
                    typeof input === "string"
                        ? input
                        : input instanceof URL
                          ? input.toString()
                          : null;

                if (!inputUrl) {
                    return originalFetch(input, init);
                }

                let requestUrl;
                try {
                    requestUrl = new URL(inputUrl, window.location.href);
                } catch {
                    return originalFetch(input, init);
                }

                if (!requestUrl.pathname.includes(":streamGenerateContent")) {
                    return originalFetch(input, init);
                }

                const response = await originalFetch(input, init);
                if (response.status !== 403) {
                    return response;
                }

                let errorBody = "";
                try {
                    errorBody = await response.clone().text();
                } catch {
                    return response;
                }

                if (!errorBody.includes("PERMISSION_DENIED")) {
                    return response;
                }

                const fallbackUrl = new URL(requestUrl.toString());
                fallbackUrl.pathname = fallbackUrl.pathname.replace(
                    ":streamGenerateContent",
                    ":generateContent"
                );
                fallbackUrl.searchParams.delete("alt");

                console.warn(
                    "[ChangAn] streamGenerateContent returned 403 PERMISSION_DENIED; retrying once with generateContent before exposing a response to the client."
                );

                const fallbackResponse = await originalFetch(fallbackUrl.toString(), init);
                if (!fallbackResponse.ok) {
                    console.warn(
                        "[ChangAn] Automatic fake-stream fallback also failed with HTTP " +
                            fallbackResponse.status +
                            "; returning the fallback error."
                    );
                    return fallbackResponse;
                }

                const fullBody = await fallbackResponse.text();
                const sseBody =
                    fullBody
                        .split(/\r?\n/)
                        .map(function (line) {
                            return "data: " + line;
                        })
                        .join("\n") + "\n\n";

                const headers = new Headers(fallbackResponse.headers);
                headers.set("content-type", "text/event-stream; charset=utf-8");
                headers.set("x-changan-stream-fallback", "fake");
                headers.delete("content-length");
                headers.delete("content-encoding");
                headers.delete("transfer-encoding");

                return new Response(sseBody, {
                    headers,
                    status: fallbackResponse.status,
                    statusText: fallbackResponse.statusText,
                });
            };
        })();
    `;

    return `${baseScript}
${autoStreamFallbackScript}`;
};

// Keep the internal browser WebSocket private. The injected browser client already
// connects to ws://127.0.0.1:9998, so there is no reason to bind this port publicly.
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
            "[Hardening] Streaming mode: auto (real first; 403 PERMISSION_DENIED falls back once to fake streaming)."
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
            browserConnected,
            busy,
            currentAuthIndex,
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
