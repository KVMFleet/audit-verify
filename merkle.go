package main

// RFC 6962 Merkle tree primitives.
//
// Mirrors platform/app/services/merkle.py byte-for-byte. The platform
// builder writes audit_merkle_epochs.merkle_root and the inclusion-
// proof endpoint emits paths in this format; the verifier here
// recomputes the root from (leaf, path, leaf_index, tree_size) and
// compares.
//
// Both sides are tested against the same cross-language fixture
// (7 leaves "leaf-0".."leaf-6" → root
// 0b007fb915eb9b2a146f54b1c86ec53b664f8e455b7660b0b6ee13edc0d921c0).

import (
	"crypto/sha256"
)

var (
	leafPrefix = []byte{0x00}
	nodePrefix = []byte{0x01}
)

// emptyRoot is SHA-256("") per RFC 6962 §2.1.
var emptyRoot []byte

func init() {
	h := sha256.New()
	emptyRoot = h.Sum(nil)
}

func merkleLeafHash(data []byte) []byte {
	h := sha256.New()
	h.Write(leafPrefix)
	h.Write(data)
	return h.Sum(nil)
}

func merkleNodeHash(left, right []byte) []byte {
	h := sha256.New()
	h.Write(nodePrefix)
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

// largestPow2LessThan returns the largest 2^k strictly less than n.
// Defined for n >= 2.
func largestPow2LessThan(n int) int {
	k := 1
	for (k << 1) < n {
		k <<= 1
	}
	return k
}

// merkleTreeHash computes the RFC-6962 MTH over a list of leaf
// inputs. Exported (lowercased name unexported but the function is
// package-visible) for use by tests + future tooling. The verifier
// itself does not need this — it only RE-checks proofs — but
// keeping it close avoids reimplementing the same algorithm in
// test files.
func merkleTreeHash(leaves [][]byte) []byte {
	if len(leaves) == 0 {
		return emptyRoot
	}
	hashes := make([][]byte, len(leaves))
	for i, d := range leaves {
		hashes[i] = merkleLeafHash(d)
	}
	return mthLeafHashes(hashes)
}

func mthLeafHashes(h [][]byte) []byte {
	if len(h) == 1 {
		return h[0]
	}
	k := largestPow2LessThan(len(h))
	return merkleNodeHash(mthLeafHashes(h[:k]), mthLeafHashes(h[k:]))
}

// auditPath returns the RFC-6962 audit (inclusion) path for
// leaves[index]. Symmetric with the Python builder in
// platform/app/services/merkle.py.
func auditPath(leaves [][]byte, index int) [][]byte {
	if index < 0 || index >= len(leaves) {
		return nil
	}
	hashes := make([][]byte, len(leaves))
	for i, d := range leaves {
		hashes[i] = merkleLeafHash(d)
	}
	return pathLeafHashes(hashes, index)
}

func pathLeafHashes(h [][]byte, m int) [][]byte {
	n := len(h)
	if n == 1 {
		return nil
	}
	k := largestPow2LessThan(n)
	if m < k {
		return append(pathLeafHashes(h[:k], m), mthLeafHashes(h[k:]))
	}
	return append(pathLeafHashes(h[k:], m-k), mthLeafHashes(h[:k]))
}

// verifyInclusion checks an RFC 6962 audit proof. Returns true iff
// `path` reconstructs `expectedRoot` from `leafHash(leafData)` at
// position `leafIndex` in a tree of size `treeSize`.
//
// This matches the algorithm in platform/app/services/merkle.py's
// verify_inclusion — both sides accept paths produced by either
// builder.
func verifyInclusion(
	leafData []byte, leafIndex, treeSize int,
	path [][]byte, expectedRoot []byte,
) bool {
	if leafIndex < 0 || leafIndex >= treeSize {
		return false
	}
	if treeSize == 0 {
		return false
	}
	if treeSize == 1 {
		if len(path) != 0 {
			return false
		}
		return bytesEqual(merkleLeafHash(leafData), expectedRoot)
	}

	fn, sn := leafIndex, treeSize-1
	r := merkleLeafHash(leafData)
	for _, p := range path {
		if sn == 0 {
			return false
		}
		if (fn&1) != 0 || fn == sn {
			r = merkleNodeHash(p, r)
			if (fn & 1) == 0 {
				for fn != 0 && (fn&1) == 0 {
					fn >>= 1
					sn >>= 1
				}
			}
		} else {
			r = merkleNodeHash(r, p)
		}
		fn >>= 1
		sn >>= 1
	}
	if sn != 0 {
		return false
	}
	return bytesEqual(r, expectedRoot)
}
