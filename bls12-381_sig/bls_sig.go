package bls12381_sig

import (
	"errors"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark/frontend"
	// sw_bls12381 "github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
)

const g2_dst = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"

func BLSVerify(pub bls12381.G1Affine, sig bls12381.G2Affine, g1GN bls12381.G1Affine, h bls12381.G2Affine) (int, error) {
	bool, e := bls12381.PairingCheck([]bls12381.G1Affine{g1GN, pub}, []bls12381.G2Affine{sig, h})
	if e != nil {
		return 0, e
	}
	if bool {
		return 1, nil
	} else {
		return 0, nil
	}
}

func BlsAssertG2Verification(api frontend.API, pub bls12381.G1Affine, sig bls12381.G2Affine, msg []byte) error {
	// public key cannot be infinity
	xtest := pub.X.IsZero()
	ytest := pub.Y.IsZero()
	if xtest && ytest {
		return errors.New("public key is infinity point")
	}

	// prime order subgroup checks
	if !pub.IsInSubGroup() {
		return errors.New("public key is not in subgroup")
	}
	if !sig.IsInSubGroup() {
		return errors.New("signature is not in subgroup")
	}

	var g1GNeg bls12381.G1Affine
	_, _, g1Gen, _ := bls12381.Generators()
	g1GNeg.Neg(&g1Gen)
	g1GN := g1GNeg

	h, e := bls12381.HashToG2(msg, []byte(g2_dst))
	if e != nil {
		return e
	}

	bool, e := bls12381.PairingCheck([]bls12381.G1Affine{g1GN, pub}, []bls12381.G2Affine{sig, h})
	if e != nil {
		return e
	}

	if !bool {
		return errors.New("pairing check failed")
	}
	return nil
}
