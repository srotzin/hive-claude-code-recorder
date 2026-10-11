// Loader for hive_shared_key.wasm. Works in Node 20+ and in browsers; no dependencies.
//   const sk = await loadSharedKey(bytes);   sk.call("dkg1", { id: 1, min: 2, max: 3 })
// Every call returns the "ok" value or throws an Error carrying the refusal text.
export async function loadSharedKey(bytes) {
  let mem;
  const env = {
    hive_random(p, n) {
      const v = new Uint8Array(mem.buffer, p, n);
      for (let i = 0; i < n; i += 65536) globalThis.crypto.getRandomValues(v.subarray(i, Math.min(n, i + 65536)));
    },
  };
  const { instance } = await WebAssembly.instantiate(bytes, { env });
  const x = instance.exports; mem = x.memory;
  const te = new TextEncoder(), td = new TextDecoder();
  function call(fn, args = {}) {
    const inb = te.encode(JSON.stringify({ fn, args }));
    const p = x.hive_alloc(inb.length);
    new Uint8Array(mem.buffer, p, inb.length).set(inb);
    const r = BigInt.asUintN(64, x.hive_call(p, inb.length));
    x.hive_free(p, inb.length);
    const op = Number(r >> 32n), ol = Number(r & 0xffffffffn);
    const out = JSON.parse(td.decode(new Uint8Array(mem.buffer, op, ol).slice()));
    x.hive_free(op, ol);
    if ("error" in out) throw Object.assign(new Error(out.error), { refused: true });
    return out.ok;
  }
  return { call };
}
// Node helper: load the wasm that sits next to this file.
export async function loadSharedKeyNode() {
  const fs = await import("node:fs"), url = await import("node:url");
  return loadSharedKey(fs.readFileSync(url.fileURLToPath(new URL("./dist/hive_shared_key.wasm", import.meta.url))));
}
