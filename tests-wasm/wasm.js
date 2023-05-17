const child_process = require('child_process');
const assert = require('assert');
const test = require('node:test');
const wasm = require('../build/tests-wasm/wasm');

function toJS(obj) {
  const result = {};
  for (const key of Object.keys(obj.__proto__)) {
       result[key] = typeof obj[key] === "object" ? toJS(obj[key]) : obj[key];
  }
  return result;
}

const expected = {
  "result": "success",
  "href": "https://google.com/?q=Yagiz#Nizipli",
  "type": 2,
  "components": {
    "protocol_end": 6,
    "username_end": 8,
    "host_start": 8,
    "host_end": 18,
    "port": 4294967295,
    "pathname_start": 18,
    "search_start": 19,
    "hash_start": 27
  }
};

test('wasm', async () => {
  const { parse } = await wasm();
  console.log();
  assert.deepStrictEqual(toJS(parse('https://google.com/?q=Yagiz#Nizipli')), expected);
});