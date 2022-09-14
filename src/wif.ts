import baseX from "base-x";

import { sha256 } from "./sha256";

const base58Codec = baseX(
  "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
);

export function encodeWif(secret: Uint8Array, compressed: boolean): string {
  const bytes = new Uint8Array(secret.length + (compressed ? 6 : 5));
  bytes[0] = 0x80;
  bytes.set(secret, 1);
  if (compressed) bytes.set([0x01], secret.length + 1);
  const checksum = sha256(sha256(bytes.subarray(0, -4))).slice(0, 4);
  bytes.set(checksum, bytes.length - 4);
  return base58Codec.encode(bytes);
}
