/* Ensure fetch is available on the global object for jsdom-based tests.
   Some jsdom versions omit it; this fallback lets tests spy on global.fetch. */
if (typeof globalThis.fetch === "undefined") {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  globalThis.fetch = require("undici").fetch;
}

import "@testing-library/jest-dom";
