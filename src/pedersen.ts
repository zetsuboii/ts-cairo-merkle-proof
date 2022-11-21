/**
 * @file pedersen.ts
 * Typescript implementation of the pedersen hash code on:
 * https://github.com/starkware-libs/starkex-resources/blob/master/crypto/starkware/crypto/signature/signature.js#L82
 */

import { BN } from "bn.js";
import { curves as eCurves, ec as EllipticCurve } from "elliptic";
import hash from "hash.js";
import assert from "assert";
import constantPointsHex from "./constantPoints.json";

const prime = new BN(
  "800000000000011000000000000000000000000000000000000000000000001",
  16
);
const zeroBN = new BN("0", 16);
const oneBN = new BN("1", 16);

const starkEc = new EllipticCurve(
  new eCurves.PresetCurve({
    type: "short",
    prime: null,
    p: prime.toString(),
    a: "00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000001",
    b: "06f21413 efbe40de 150e596d 72f7a8c5 609ad26c 15c915c1 f4cdfcb9 9cee9e89",
    n: "08000000 00000010 ffffffff ffffffff b781126d cae7b232 1e66a241 adc64d2f",
    hash: hash.sha256,
    gRed: false,
    g: constantPointsHex[1],
  })
);

const constantPoints = constantPointsHex.map((coords) =>
  starkEc.curve.point(new BN(coords[0], 16), new BN(coords[1], 16))
);

const shiftPoint = constantPoints[0];

/**
 * Hashes input array using Pedersen hash
 * @param input Input to hash
 * @returns Pedersen hash
 */
export function pedersen(input: string[]): string {
  let point = shiftPoint;
  for (let i = 0; i < input.length; i++) {
    let x = new BN(input[i], 16);
    assert(x.gte(zeroBN) && x.lt(prime), "Invalid input: " + input[i]);
    for (let j = 0; j < 252; j++) {
      const pt = constantPoints[2 + i * 252 + j];
      assert(!point.getX().eq(pt.getX()));
      if (x.and(oneBN).toNumber() !== 0) {
        point = point.add(pt);
      }
      x = x.shrn(1);
    }
  }
  return point.getX().toString(16);
}
