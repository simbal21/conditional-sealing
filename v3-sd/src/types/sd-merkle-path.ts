// App. I.8 `SdMerklePathElement` — single Merkle path element. Verbatim from
// §App.I lines 2331-2336.
//
// Path ordering: LEAF-TO-ROOT.
//   direction = 0 → current node is LEFT child, sibling is right child.
//   direction = 1 → current node is RIGHT child, sibling is left child.
//
// This convention is BOTH circuit-visible AND SDK-visible (§I.8 line 2338).

import type { HexScalar } from "./sd-bundle.js";

export type MerkleDirectionBit = 0 | 1;

/**
 *   type SdMerklePathElement = {
 *     sibling: HexScalar;
 *     direction: 0 | 1;
 *   };
 */
export interface SdMerklePathElement {
  readonly sibling: HexScalar;
  readonly direction: MerkleDirectionBit;
}
