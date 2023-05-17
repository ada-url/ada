const child_process = require('child_process');
const assert = require('assert');
const test = require('node:test');

const expected = {
  "buffer": "https://google.com/?q=Yagiz#Nizipli",
  "protocol": "https:",
  "host": "google.com",
  "path": "/",
  "opaque path": false,
  "query": "?q=Yagiz",
  "fragment": "#Nizipli",
  "protocol_end": 6,
  "username_end": 8,
  "host_start": 8,
  "host_end": 18,
  "port": null,
  "pathname_start": 18,
  "search_start": 19,
  "hash_start": 27
};

test('wasm', () => {
  const { stdout } = child_process.spawnSync(process.execPath, ['./build/tools/cli/adaparse.js', 'https://google.com/?q=Yagiz#Nizipli'])
  assert.deepStrictEqual(JSON.parse(stdout), expected);
});