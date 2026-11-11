import { ZodError } from "zod";
export function notFound(_req, res) { res.status(404).json({ error: { code: "NOT_FOUND", message: "Resource not found." } }); }
export function errorHandler(err, _req, res, _next) {
  if (err instanceof ZodError) {
    const message = err.issues.map((i) => `${i.path.join(".") || "body"}: ${i.message}`).join("; ");
    return res.status(400).json({ error: { code: "VALIDATION_ERROR", message } });
  }
  if (err.status) return res.status(err.status).json({ error: { code: err.code, message: err.message } });
  if (err.name === "CastError") return res.status(400).json({ error: { code: "INVALID_ID", message: "Invalid identifier." } });
  console.error("[error]", err); // stack stays server-side; client gets a generic message (SRS UI-05)
  res.status(500).json({ error: { code: "INTERNAL_ERROR", message: "Something went wrong. Please try again." } });
}
