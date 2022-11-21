import BN from "bn.js";
import { pedersen } from "./pedersen";

/** [ pedersen(recipient, amount), recipient, amount ] */
export type Leaf = [string, string, string];

/**
 * Generate merkle root, given leaves
 * @param values 
 * @returns Merkle root
 */
export function generateMerkleRoot(values: string[]): string {
  if (values.length === 1) {
    return values[0];
  }

  if (values.length % 2 != 0) values.push("0");

  const nextLevel = getNextLevel(values.map((v) => new BN(v)));
  return generateMerkleRoot(nextLevel.map((nl) => nl.toString()));
}

/**
 * Generate merkle proof for an index, given leaves and index
 * @param values 
 * @param index 
 * @returns Merkle proof
 */
export function generateMerkleProof(values: string[], index: number): BN[] {
  return generateProofHelper(
    values.map((v) => new BN(v)),
    index,
    []
  );
}

/**
 * Verifies merkle proof, given leaf and proof
 * @param leaf 
 * @param proof 
 * @returns If proof is valid
 */
export function verifyMerkleProof(leaf: string, proof: string[]): boolean {
  const root = new BN(proof[proof.length - 1]);
  const proofBN = proof
    .filter((_v, i) => i != proof.length - 1)
    .map((p) => new BN(p)); // proof[:-1]

  let curr = new BN(leaf);
  for (const proofElement of proofBN) {
    if (curr.lt(proofElement)) {
      curr = new BN(pedersen([curr, proofElement].map(String)));
    } else {
      curr = new BN(pedersen([proofElement, curr].map(String)));
    }
  }

  return curr.eq(root);
}

export function getLeaves(recipients: string[], amounts: string[]): Leaf[] {
  const values: Leaf[] = [];

  for (let i = 0; i < recipients.length; i++) {
    const leaf = getLeaf(recipients[i], amounts[i]);
    const value: Leaf = [leaf, recipients[i], amounts[i]];
    values.push(value);
  }

  if (values.length % 2 != 0) {
    const lastValue: Leaf = ["0", "0", "0"];
    values.push(lastValue);
  }

  return values;
}

function getLeaf(recipient: string, amount: string) {
  const amountHash = pedersen([amount, "0"]);
  const leaf = pedersen([recipient, amountHash]);
  return leaf;
}

function getNextLevel(level: BN[]): BN[] {
  const nextLevel: BN[] = [];

  for (let i = 0; i < level.length; i++) {
    let node: BN = new BN(0);

    if (level[i].lt(level[i + 1])) {
      node = new BN(pedersen([level[i], level[i + 1]].map(String)));
    } else {
      node = new BN(pedersen([level[i + 1], level[i]].map(String)));
    }

    nextLevel.push(node);
  }

  return nextLevel;
}

function generateProofHelper(level: BN[], index: number, proof: BN[]): BN[] {
  if (level.length === 1) return proof;
  if (level.length % 2 != 0) level.push(new BN("0"));

  const nextLevel = getNextLevel(level);
  let indexParent = 0;

  for (let i = 0; i < level.length; i++) {
    if (i == index) {
      indexParent = i; // 2
      if (i % 2 == 0) proof.push(level[index + 1]);
      else proof.push(level[index - 1]);
    }
  }

  return generateProofHelper(nextLevel, indexParent, proof);
}
