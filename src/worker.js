// Worker entry point (wrangler.toml `main`).
//
// workerd only accepts handlers (functions / ExportedHandler objects) as exports
// of the entry module. src/index.js also exports plain values for the tests
// (HARDEN_TOOL_NAME, RESPONSE_SCHEMA, the rate-limit constants), which makes the
// runtime refuse to start if it is used as the entry directly. So the entry is
// this thin file that re-exports only the default handler.
import worker from "./index.js";

export default worker;
