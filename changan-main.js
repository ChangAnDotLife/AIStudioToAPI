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
const ConfigLoader = require("./src/utils/ConfigLoader");
const StatusRoutes = require("./src/routes/StatusRoutes");

const DEFAULT_AI_STUDIO_APP_URL = "https://ai.studio/apps/cab9ab6c-44f9-4e7a-8972-037f8ae177ab";
const DEFAULT_MAX_REQUEST_BODY_BYTES = 64 * 1024 * 1024;
const INTERNAL_WS_HOST = "127.0.0.1";

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

// Fail closed in production instead of silently exposing the upstream default key "123456".
const originalLoadConfiguration = ConfigLoader.prototype.loadConfiguration;
ConfigLoader.prototype.loadConfiguration = function loadHardenedConfiguration() {
    if (process.env.NODE_ENV === "production" && !hasConfiguredApiKey()) {
        throw new Error("API_KEYS is required in production; refusing to use the insecure default key.");
    }

    const config = originalLoadConfiguration.call(this);
    config.maxRequestBodyBytes = getRequestBodyLimit();
    config.aiStudioAppUrl = getAiStudioAppUrl();
    return config;
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

        return res.status(ready ? 200 : 503).json({
            authAvailable,
            browserConnected,
            busy,
            currentAuthIndex,
            ready,
            wsConnected,
        });
    });

    return originalSetupRoutes.call(this, app, isAuthenticated);
};

initializeServer();
