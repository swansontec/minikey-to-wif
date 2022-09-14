import { describe, it } from "mocha";
import { base16 } from "rfc4648";
import { encodeWif } from "../src/wif";

describe("encodeWif", function () {
  it("Follows the example on the Bitcoin Wiki", function () {
    const secret = base16.parse(
      "0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D"
    );
    const expected = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ";
    const wif = encodeWif(secret, false);

    if (wif !== expected) {
      throw new Error(`Got ${wif}, expected ${expected}`);
    }
  });
});
