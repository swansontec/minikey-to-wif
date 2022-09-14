import hashjs from "hash.js";

export function sha256(data: Uint8Array): Uint8Array {
  const hash = hashjs.sha256();
  return Uint8Array.from(hash.update(data).digest());
}
