/* Ensure fetch is available on the global object for jsdom-based tests.
   Some jsdom versions omit it; this fallback lets tests spy on global.fetch. */
import { TextEncoder, TextDecoder } from 'util';
import { ReadableStream, WritableStream, TransformStream } from 'stream/web';
import { MessageChannel, MessagePort } from 'worker_threads';

Object.assign(globalThis, { 
  TextDecoder, 
  TextEncoder,
  ReadableStream,
  WritableStream,
  TransformStream,
  MessageChannel,
  MessagePort
});

if (typeof globalThis.fetch === "undefined") {
  const undici = require("undici");
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  globalThis.fetch = undici.fetch as typeof fetch;
  globalThis.Request = undici.Request as typeof Request;
  globalThis.Response = undici.Response as typeof Response;
  globalThis.Headers = undici.Headers as typeof Headers;
}

import "@testing-library/jest-dom";
