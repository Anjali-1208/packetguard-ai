// OpenAPI 3.0 spec for the PacketGuard AI backend.
// Mounted at /api/docs (UI) and /api/docs.json (raw spec) in src/index.js.

const ref = (n) => ({ $ref: `#/components/schemas/${n}` });
const json = (schema) => ({ "application/json": { schema } });
const ok = (description, schema) => ({ description, ...(schema && { content: json(schema) }) });
const err = (description) => ({ description, content: json(ref("Error")) });
const idParam = (name, desc, type = "string") => ({ name, in: "path", required: true, description: desc, schema: { type } });
const secured = [{ bearerAuth: [] }];

const alertFilters = [
  { name: "severity", in: "query", schema: { type: "string", enum: ["low", "medium", "high", "critical"] } },
  { name: "status", in: "query", schema: { type: "string", enum: ["new", "acknowledged", "blocked", "resolved", "false_positive"] } },
  { name: "srcIp", in: "query", schema: { type: "string", maxLength: 45 } },
  { name: "from", in: "query", schema: { type: "string", format: "date-time" } },
  { name: "to", in: "query", schema: { type: "string", format: "date-time" } },
  { name: "sort", in: "query", schema: { type: "string", enum: ["severity", "recent"], default: "severity" } },
];
const paging = [
  { name: "page", in: "query", schema: { type: "integer", minimum: 1, default: 1 } },
  { name: "limit", in: "query", schema: { type: "integer", minimum: 1, maximum: 200, default: 50 } },
];

export const openapi = {
  openapi: "3.0.3",
  info: {
    title: "PacketGuard AI API",
    version: "1.0.0",
    description:
      "REST API for the PacketGuard AI intrusion-detection dashboard.\n\n" +
      "**Auth:** call `POST /api/auth/login`, copy `accessToken`, click **Authorize** and paste it (no `Bearer ` prefix). " +
      "Access tokens last 15 minutes; use `POST /api/auth/refresh` to rotate.\n\n" +
      "Severity and verdict are recommendations; the block decision always belongs to the analyst.",
  },
  servers: [{ url: "/", description: "Current host" }, { url: "http://localhost:5000", description: "Local" }],
  tags: [
    { name: "Auth" }, { name: "Alerts" }, { name: "Block Rules" }, { name: "Stats" },
    { name: "Threat Intel" }, { name: "Notifications" }, { name: "Admin" }, { name: "System" },
  ],
  components: {
    securitySchemes: { bearerAuth: { type: "http", scheme: "bearer", bearerFormat: "JWT" } },
    schemas: {
      Error: {
        type: "object",
        properties: { error: { type: "object", properties: { code: { type: "string", example: "NOT_FOUND" }, message: { type: "string" } } } },
      },
      User: {
        type: "object",
        properties: { id: { type: "integer" }, name: { type: "string" }, email: { type: "string", format: "email" }, role: { type: "string", enum: ["analyst", "admin"] } },
      },
      AuthResponse: {
        type: "object",
        properties: { accessToken: { type: "string" }, refreshToken: { type: "string" }, expiresIn: { type: "integer", example: 900 }, user: ref("User") },
      },
      Alert: {
        type: "object",
        properties: {
          id: { type: "string" }, createdAt: { type: "string", format: "date-time" },
          severity: { type: "string", enum: ["low", "medium", "high", "critical"] },
          status: { type: "string", enum: ["new", "acknowledged", "blocked", "resolved", "false_positive"] },
          verdict: { type: "string" }, supervisedLabel: { type: "string" }, supervisedConfidence: { type: "number" },
          anomalyScore: { type: "number" }, srcIp: { type: "string" }, dstIp: { type: "string" }, dstPort: { type: "integer" },
          statusReason: { type: "string" }, blockRuleId: { type: "integer", nullable: true },
        },
      },
      BlockRule: {
        type: "object",
        properties: {
          id: { type: "integer" }, ip: { type: "string", example: "192.0.2.10" }, reason: { type: "string" },
          active: { type: "boolean" }, alertId: { type: "string" }, createdAt: { type: "string", format: "date-time" },
          createdBy: { type: "object", properties: { id: { type: "integer" }, name: { type: "string" }, email: { type: "string" } } },
        },
      },
      Thresholds: {
        type: "object", required: ["critical", "high", "anomaly_high"],
        properties: {
          critical: { type: "number", minimum: 0.5, maximum: 1, example: 0.9 },
          high: { type: "number", minimum: 0.1, maximum: 1, example: 0.7, description: "Must be lower than critical" },
          anomaly_high: { type: "number", minimum: -1, maximum: 0, example: -0.1 },
        },
      },
    },
    responses: {
      Unauthorized: err("Missing or invalid access token"),
      Forbidden: err("Role not permitted"),
      NotFound: err("Resource not found"),
      Conflict: err("State conflict (e.g. invalid status transition)"),
      Validation: err("Request failed validation"),
    },
  },
  paths: {
    "/health": { get: { tags: ["System"], summary: "Liveness probe", responses: { 200: ok("OK", { type: "object", properties: { status: { type: "string" }, mongo: { type: "boolean" } } }) } } },

    // ---------- Auth ----------
    "/api/auth/register": {
      post: {
        tags: ["Auth"], summary: "Self-register an analyst (if enabled)",
        requestBody: { required: true, content: json({ type: "object", required: ["name", "email", "password"],
          properties: { name: { type: "string", minLength: 2, maxLength: 80 }, email: { type: "string", format: "email" },
            password: { type: "string", minLength: 8, description: "Needs upper, lower and a digit" } } }) },
        responses: { 201: ok("Created", ref("AuthResponse")), 403: err("Registration disabled"), 409: err("Email exists") },
      },
    },
    "/api/auth/login": {
      post: {
        tags: ["Auth"], summary: "Log in",
        requestBody: { required: true, content: json({ type: "object", required: ["email", "password"],
          properties: { email: { type: "string", format: "email", example: "analyst@packetguard.local" }, password: { type: "string", example: "Analyst123" } } }) },
        responses: { 200: ok("Tokens issued (refresh token also set as httpOnly cookie)", ref("AuthResponse")), 401: err("Invalid credentials"), 403: err("Locked or suspended"), 429: err("Rate limited") },
      },
    },
    "/api/auth/refresh": {
      post: {
        tags: ["Auth"], summary: "Rotate refresh token",
        requestBody: { content: json({ type: "object", properties: { refreshToken: { type: "string" } } }) },
        responses: { 200: ok("New tokens", ref("AuthResponse")), 401: err("Invalid or expired session") },
      },
    },
    "/api/auth/logout": {
      post: { tags: ["Auth"], summary: "Revoke refresh token", responses: { 200: ok("Logged out", { type: "object", properties: { ok: { type: "boolean" } } }) } },
    },
    "/api/auth/me": {
      get: { tags: ["Auth"], summary: "Current user", security: secured, responses: { 200: ok("User", { type: "object", properties: { user: ref("User") } }), 401: ref401() } },
    },

    // ---------- Alerts ----------
    "/api/alerts": {
      get: {
        tags: ["Alerts"], summary: "List alerts", security: secured, parameters: [...alertFilters, ...paging],
        responses: { 200: ok("Page of alerts", { type: "object", properties: { alerts: { type: "array", items: ref("Alert") }, total: { type: "integer" }, page: { type: "integer" }, limit: { type: "integer" }, note: { type: "string" } } }), 401: ref401() },
      },
    },
    "/api/alerts/export": {
      get: {
        tags: ["Alerts"], summary: "Export alerts as CSV (max 5000 rows)", security: secured, parameters: alertFilters,
        responses: { 200: { description: "CSV file", content: { "text/csv": { schema: { type: "string", format: "binary" } } } }, 401: ref401() },
      },
    },
    "/api/alerts/{id}": {
      get: {
        tags: ["Alerts"], summary: "Alert detail with flow, threat intel and related alerts", security: secured,
        parameters: [idParam("id", "Alert id (Mongo ObjectId)")],
        responses: { 200: ok("Alert detail", { type: "object", properties: { alert: ref("Alert"), flow: { type: "object" }, threatIntel: { type: "object", nullable: true }, related: { type: "array", items: ref("Alert") }, note: { type: "string" } } }), 401: ref401(), 404: { $ref: "#/components/responses/NotFound" } },
      },
    },
    "/api/alerts/{id}/status": {
      patch: {
        tags: ["Alerts"], summary: "Change alert status", security: secured, parameters: [idParam("id", "Alert id")],
        requestBody: { required: true, content: json({ type: "object", required: ["status"],
          properties: { status: { type: "string", enum: ["acknowledged", "resolved", "false_positive"], description: "Lowercase. 'blocked' is set via /block." }, reason: { type: "string", maxLength: 500 } } }) },
        responses: { 200: ok("Updated", { type: "object", properties: { alert: ref("Alert") } }), 404: { $ref: "#/components/responses/NotFound" }, 409: { $ref: "#/components/responses/Conflict" } },
      },
    },
    "/api/alerts/{id}/block": {
      post: {
        tags: ["Alerts"], summary: "Approve a block (alert must be acknowledged). Creates the BlockRule.", security: secured,
        description: "Roles: analyst, admin.", parameters: [idParam("id", "Alert id")],
        requestBody: { required: true, content: json({ type: "object", required: ["reason"], properties: { reason: { type: "string", minLength: 3, maxLength: 500 } } }) },
        responses: { 201: ok("Block rule created or reused", { type: "object", properties: { blockRuleId: { type: "integer" }, ip: { type: "string" }, active: { type: "boolean" } } }), 403: { $ref: "#/components/responses/Forbidden" }, 404: { $ref: "#/components/responses/NotFound" }, 409: { $ref: "#/components/responses/Conflict" } },
      },
    },

    // ---------- Block rules ----------
    "/api/blockrules": {
      get: { tags: ["Block Rules"], summary: "List block rules", security: secured, responses: { 200: ok("Rules", { type: "object", properties: { rules: { type: "array", items: ref("BlockRule") } } }), 401: ref401() } },
    },
    "/api/blockrules/{id}": {
      patch: {
        tags: ["Block Rules"], summary: "Update a rule (admin only)", security: secured, parameters: [idParam("id", "Rule id", "integer")],
        requestBody: { required: true, content: json({ type: "object", properties: { active: { type: "boolean" }, reason: { type: "string", minLength: 3, maxLength: 500 } } }) },
        responses: { 200: ok("Updated", { type: "object", properties: { rule: ref("BlockRule") } }), 400: err("Invalid id"), 403: { $ref: "#/components/responses/Forbidden" }, 404: { $ref: "#/components/responses/NotFound" } },
      },
    },

    // ---------- Stats / intel / notifications ----------
    "/api/stats/summary": {
      get: { tags: ["Stats"], summary: "Dashboard summary", security: secured,
        parameters: [{ name: "minutes", in: "query", schema: { type: "integer", minimum: 5, maximum: 240, default: 30 } }],
        responses: { 200: ok("Summary", { type: "object" }) } },
    },
    "/api/stats/model-performance": {
      get: { tags: ["Stats"], summary: "ML model metrics (proxied from ml-service)", security: secured, responses: { 200: ok("Metrics", { type: "object" }), 502: err("ML service unavailable") } },
    },
    "/api/threatintel/{ip}": {
      get: { tags: ["Threat Intel"], summary: "Threat-intel lookup for an IP", security: secured,
        parameters: [idParam("ip", "IPv4 / IPv6"), { name: "refresh", in: "query", schema: { type: "string", enum: ["1"] }, description: "Force re-lookup" }],
        responses: { 200: ok("Intel", { type: "object" }), 400: { $ref: "#/components/responses/Validation" } } },
    },
    "/api/notifications": {
      get: { tags: ["Notifications"], summary: "Latest 50 notifications for current user", security: secured, responses: { 200: ok("Notifications", { type: "object", properties: { notifications: { type: "array", items: { type: "object" } }, unread: { type: "integer" } } }) } },
    },
    "/api/notifications/read-all": {
      post: { tags: ["Notifications"], summary: "Mark all read", security: secured, responses: { 200: ok("OK") } },
    },
    "/api/notifications/{id}/read": {
      patch: { tags: ["Notifications"], summary: "Mark one read", security: secured, parameters: [idParam("id", "Notification id")], responses: { 200: ok("OK") } },
    },

    // ---------- Admin ----------
    "/api/admin/users": {
      get: { tags: ["Admin"], summary: "List users (admin)", security: secured, responses: { 200: ok("Users", { type: "object", properties: { users: { type: "array", items: ref("User") } } }), 403: { $ref: "#/components/responses/Forbidden" } } },
      post: { tags: ["Admin"], summary: "Create user (admin)", security: secured,
        requestBody: { required: true, content: json({ type: "object", required: ["name", "email", "password"],
          properties: { name: { type: "string" }, email: { type: "string", format: "email" }, password: { type: "string" }, role: { type: "string", enum: ["analyst", "admin"], default: "analyst" } } }) },
        responses: { 201: ok("Created", { type: "object", properties: { user: ref("User") } }), 409: err("Email exists") } },
    },
    "/api/admin/users/{id}": {
      patch: { tags: ["Admin"], summary: "Change role / suspend (admin; not yourself)", security: secured, parameters: [idParam("id", "User id", "integer")],
        requestBody: { required: true, content: json({ type: "object", properties: { status: { type: "string", enum: ["active", "suspended"] }, role: { type: "string", enum: ["analyst", "admin"] } } }) },
        responses: { 200: ok("Updated", { type: "object", properties: { user: ref("User") } }), 404: { $ref: "#/components/responses/NotFound" }, 409: err("Self-modification") } },
    },
    "/api/admin/config": {
      get: { tags: ["Admin"], summary: "Get severity thresholds", security: secured, responses: { 200: ok("Thresholds", { type: "object", properties: { thresholds: ref("Thresholds") } }) } },
      patch: { tags: ["Admin"], summary: "Update severity thresholds", security: secured, requestBody: { required: true, content: json(ref("Thresholds")) },
        responses: { 200: ok("Saved", { type: "object", properties: { thresholds: ref("Thresholds") } }), 400: { $ref: "#/components/responses/Validation" } } },
    },
    "/api/admin/audit-logs": {
      get: { tags: ["Admin"], summary: "Audit log (admin)", security: secured,
        parameters: [{ name: "actor", in: "query", schema: { type: "string" } }, { name: "action", in: "query", schema: { type: "string" } },
          { name: "from", in: "query", schema: { type: "string", format: "date-time" } }, { name: "to", in: "query", schema: { type: "string", format: "date-time" } }, ...paging],
        responses: { 200: ok("Logs", { type: "object", properties: { logs: { type: "array", items: { type: "object" } }, total: { type: "integer" }, page: { type: "integer" } } }) } },
    },
    "/api/admin/health": {
      get: { tags: ["Admin"], summary: "Component health (admin)", security: secured, responses: { 200: ok("Health", { type: "object" }) } },
    },
  },
};

function ref401() { return { $ref: "#/components/responses/Unauthorized" }; }
