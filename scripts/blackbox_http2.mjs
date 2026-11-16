#!/usr/bin/env node
// Exercise an actual broker CONNECT tunnel against a publicly trusted HTTP/2 origin.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http2 from 'node:http2';
import net from 'node:net';
import tls from 'node:tls';
import { once } from 'node:events';

const proxy = new URL(process.env.ABYSS_HTTP2_PROXY_URL);
const origin = new URL(process.env.ABYSS_HTTP2_ORIGIN ?? 'https://httpbingo.org');
const ca = fs.readFileSync(process.env.ABYSS_HTTP2_CA_FILE);
const tcp = net.connect(Number(proxy.port), proxy.hostname);
await once(tcp, 'connect');
tcp.write(`CONNECT ${origin.hostname}:443 HTTP/1.1\r\nHost: ${origin.hostname}:443\r\n\r\n`);
let head = Buffer.alloc(0);
for await (const chunk of tcp.iterator({ destroyOnReturn: false })) {
  head = Buffer.concat([head, chunk]);
  const end = head.indexOf('\r\n\r\n');
  if (end !== -1) {
    assert.match(head.subarray(0, end).toString(), /^HTTP\/1\.1 200 /);
    if (end + 4 < head.length) tcp.unshift(head.subarray(end + 4));
    break;
  }
}
const secure = tls.connect({ socket: tcp, servername: origin.hostname, ca, ALPNProtocols: ['h2'] });
await once(secure, 'secureConnect');
assert.equal(secure.alpnProtocol, 'h2');
const session = http2.connect(origin.origin, { createConnection: () => secure });
session.setTimeout(30_000, () => session.destroy(new Error('HTTP/2 black-box timeout')));
const marker = `abyss-http2-${Date.now()}`;
async function request(index) {
  const payload = JSON.stringify({ marker, index, data: 'x'.repeat(96 * 1024) });
  const stream = session.request({ ':method': 'POST', ':path': process.env.ABYSS_HTTP2_PATH ?? '/post', 'content-type': 'application/json', 'user-agent': 'abyss-http2-validation/1.0' });
  let status;
  stream.on('response', (headers) => { status = headers[':status']; });
  stream.end(payload);
  const chunks = [];
  for await (const chunk of stream) chunks.push(chunk);
  assert.equal(status, 200);
  const response = JSON.parse(Buffer.concat(chunks));
  assert.deepEqual(response.json, JSON.parse(payload));
  return { index, status, echoedBytes: Buffer.byteLength(payload) };
}
try {
  const results = await Promise.all([request(1), request(2), request(3)]);
  console.log(JSON.stringify({ result: 'pass', alpn: secure.alpnProtocol, marker, results }));
} finally {
  session.close();
  await once(session, 'close');
}
