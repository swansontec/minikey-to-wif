import { encodeWif } from "./wif";
import { sha256 } from "./sha256";

const utf8 = {
  parse(text: string): Uint8Array {
    const byteString = encodeURI(text);
    const out = new Uint8Array(byteString.length);

    // Treat each character as a byte, except for %XX escape sequences:
    let di = 0; // Destination index
    for (let i = 0; i < byteString.length; ++i) {
      const c = byteString.charCodeAt(i);
      if (c === 0x25) {
        out[di++] = parseInt(byteString.slice(i + 1, i + 3), 16);
        i += 2;
      } else {
        out[di++] = c;
      }
    }

    // Trim any over-allocated space (zero-copy):
    return out.subarray(0, di);
  },
};

const hbitsKey = [
  0x9b, 0xae, 0x41, 0x66, 0x0b, 0xb8, 0x4c, 0x84, 0x39, 0x34, 0xd4, 0x6a, 0x7f,
  0x4d, 0xba, 0x04, 0x1b, 0x48, 0xc9, 0x0d, 0x7e, 0x0a, 0xe2, 0x34, 0xbe, 0x69,
  0x3a, 0x39, 0x50, 0x87, 0xaf, 0x0a,
];

/**
 * Decodes an hbits private key.
 *
 * This format is very similar to the minikey format, but with some changes:
 * - The checksum character is `!` instead of `?`.
 * - The final public key is compressed.
 * - The private key must be XOR'ed with a magic constant.
 *
 * Test vector:
 * hbits://S23c2fe8dbd330539a5fbab16a7602
 * Secret:  0x2AB7C27C5EE4E48DA1F4DDC41913B9FF87EB1438A8422B7E21AB4914F8DFD826
 * WIF:     KxekNxnLVuzQxSbu22NSK8y69HZZwmaZNsQvBLqa3cprJ1TagVfr
 * Address: 1Lbd7DZWdz7fMR1sHHnWfnfQeAFoT52ZAi
 */
function hbitsDecode(text: string): Uint8Array {
  // Extract the secret:
  const result = sha256(utf8.parse(text));

  // XOR with our magic number:
  for (let i = 0; i < hbitsKey.length && i < result.length; ++i)
    result[i] ^= hbitsKey[i];

  return result;
}

/**
 * Checks an hits key for validity.
 */
function hbitsOk(text: string): boolean {
  if (text.length != 22 && text.length != 30) return false;
  if (sha256(utf8.parse(text + "!"))[0] !== 0x00) return false;
  return true;
}

/**
 * Checks a Casascius minikey for validity.
 */
function minikeyOk(text: string): boolean {
  // Legacy minikeys are 22 chars long
  if (text.length != 22 && text.length != 30) return false;
  return sha256(utf8.parse(text + "?"))[0] === 0x00;
}

/**
 * Decodes a Casascius minikey private key.
 *
 * Example: S6c56bnXQiBjk9mqSYE7ykVQ7NzrRy
 */
function minikeyDecode(text: string): Uint8Array {
  return sha256(utf8.parse(text));
}

function processText(text: string): string {
  const noPrefix = text.replace(/^hbits:\/\//, "");
  if (hbitsOk(noPrefix)) return encodeWif(hbitsDecode(noPrefix), true);
  if (minikeyOk(text)) return encodeWif(minikeyDecode(text), false);

  return "invalid input";
}

const form = document.getElementById("form") as HTMLFormElement;
form.addEventListener("submit", (event) => {
  event.preventDefault();
  const minikey = document.getElementById("minikey") as HTMLInputElement;
  const output = document.getElementById("output") as HTMLSpanElement;
  output.innerText = processText(minikey.value);
});
