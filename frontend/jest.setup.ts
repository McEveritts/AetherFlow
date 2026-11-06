/* Ensure fetch is available on the global object for jsdom-based tests.
   Some jsdom versions omit it; this fallback lets tests spy on global.fetch. */
import { TextEncoder, TextDecoder } from 'util';
import { ReadableStream, WritableStream, TransformStream } from 'stream/web';
import { MessageChannel as NodeMessageChannel, MessagePort } from 'worker_threads';

// Preserve native asynchronous scheduling (some workspace tests depend on it)
// while closing every channel owned by this jsdom environment at teardown.
const testMessageChannels = new Set<NodeMessageChannel>();
class TestMessageChannel extends NodeMessageChannel {
  constructor() {
    super();
    testMessageChannels.add(this);
  }
}
afterAll(() => {
  for (const channel of testMessageChannels) {
    channel.port1.close();
    channel.port2.close();
  }
  testMessageChannels.clear();
});
Object.assign(globalThis, { 
  TextDecoder, 
  TextEncoder,
  ReadableStream,
  WritableStream,
  TransformStream,
  MessageChannel: TestMessageChannel,
  MessagePort
});

if (typeof globalThis.fetch === "undefined") {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const zlib = require("zlib");
  if (typeof zlib.createZstdDecompress !== "function") {
    zlib.createZstdDecompress = zlib.createGunzip;
  }
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const undici = require("undici");
  globalThis.fetch = undici.fetch as typeof fetch;
  globalThis.Request = undici.Request as typeof Request;
  globalThis.Response = undici.Response as typeof Response;
  globalThis.Headers = undici.Headers as typeof Headers;
}

import "@testing-library/jest-dom";
