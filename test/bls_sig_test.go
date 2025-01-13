package test

import (
	"encoding/hex"
	"os"
	"testing"

	// bls12381_sig "bls-verify/bls12-381_sig"

	// "github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark/frontend"
	sw_bls12381 "github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"

	// "github.com/consensys/gnark/test"
	"github.com/PolyhedraZK/ExpanderCompilerCollection/ecgo/test"

	"github.com/PolyhedraZK/ExpanderCompilerCollection/ecgo"
	"github.com/consensys/gnark-crypto/ecc"
)

const g2_dst = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"

func BLSVerify(api frontend.API, pub bls12381.G1Affine, sig bls12381.G2Affine, g1GN bls12381.G1Affine, h bls12381.G2Affine) (int, error) {
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

type BLSSigGKRCircuit struct {
	Pub bls12381.G1Affine
	msg []byte
	Sig bls12381.G2Affine
}

func (c *BLSSigGKRCircuit) Define(api frontend.API) error {
	// Check that public key is not infinity point
	// At least one of X or Y should be non-zero
	// xIsZero := c.Pub.X.IsZero()
	// yIsZero := c.Pub.Y.IsZero()
	// if xIsZero || yIsZero {
	//     infinityCheck := 1
	//     api.AssertIsEqual(infinityCheck, 0)
	// }

	// // Check points are in the prime order subgroup
	// inSubGroup1 := c.Pub.IsInSubGroup()
	// inSubGroup2 := c.Sig.IsInSubGroup()
	// if !inSubGroup1 || !inSubGroup2 {
	//     subgroupCheck := 1
	//     api.AssertIsEqual(subgroupCheck, 0)
	// }

	var g1GNeg bls12381.G1Affine
	_, _, g1Gen, _ := bls12381.Generators()
	g1GNeg.Neg(&g1Gen)
	g1GN := sw_bls12381.NewG1Affine(g1GNeg)

	h, e := bls12381.HashToG2(c.msg, []byte(g2_dst))
	if e != nil {
		return e
	}
	h_sw := sw_bls12381.NewG2Affine(h)
    pub_sw := sw_bls12381.NewG1Affine(c.Pub)
    sig_sw := sw_bls12381.NewG2Affine(c.Sig)

	pairing, err := sw_bls12381.NewPairing(api)
	if err != nil {
		return err
	}
	error := pairing.PairingCheck([]*sw_bls12381.G1Affine{&g1GN, &pub_sw}, []*sw_bls12381.G2Affine{&sig_sw, &h_sw})
	if error != nil {
		return error
	}

	// Assert pairing check result
	// if !ok {
	//     pairingCheck := 1
	//     api.AssertIsEqual(pairingCheck, 0)
	// }
	return nil
}

// "pubkey": "0xa491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a",
// "message": "0x5656565656565656565656565656565656565656565656565656565656565656",
// "signature": "0x882730e5d03f6b42c3abc26d3372625034e1d871b65a8a6b900a56dae22da98abbe1b68f85e49fe7652a55ec3d0591c20767677e33e5cbb1207315c41a9ac03be39c2e7668edc043d6cb1d9fd93033caa8a1c5b0e84bedaeb6c64972503a43eb"},
// // "output": true}
// func TestBlsSigTestSolve(t *testing.T) {
// 	assert := test.NewAssert(t)

// 	msgHex := "5656565656565656565656565656565656565656565656565656565656565656"
// 	pubHex := "a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a"
// 	sigHex := "882730e5d03f6b42c3abc26d3372625034e1d871b65a8a6b900a56dae22da98abbe1b68f85e49fe7652a55ec3d0591c20767677e33e5cbb1207315c41a9ac03be39c2e7668edc043d6cb1d9fd93033caa8a1c5b0e84bedaeb6c64972503a43eb"

// 	msgBytes := make([]byte, len(msgHex)>>1)
// 	hex.Decode(msgBytes, []byte(msgHex))
// 	pubBytes := make([]byte, len(pubHex)>>1)
// 	hex.Decode(pubBytes, []byte(pubHex))
// 	sigBytes := make([]byte, len(sigHex)>>1)
// 	hex.Decode(sigBytes, []byte(sigHex))

// 	var pub bls12381.G1Affine
// 	_, e := pub.SetBytes(pubBytes)
// 	if e != nil {
// 		t.Fail()
// 	}
// 	var sig bls12381.G2Affine
// 	_, e = sig.SetBytes(sigBytes)
// 	if e != nil {
// 		t.Fail()
// 	}

// 	var g1GNeg bls12381.G1Affine
// 	_, _, g1Gen, _ := bls12381.Generators()
// 	g1GNeg.Neg(&g1Gen)

// 	h, e := bls12381.HashToG2(msgBytes, []byte(g2_dst))
// 	if e != nil {
// 		t.Fail()
// 	}

// 	b, e := bls12381.PairingCheck([]bls12381.G1Affine{g1GNeg, pub}, []bls12381.G2Affine{sig, h})
// 	if e != nil {
// 		t.Fail()
// 	}
// 	if !b {
// 		t.Fail() // invalid inputs, won't verify
// 	}

// 	circuit := BLSSigGKRCircuit{
// 		Pub: pub,
// 		msg: msgBytes,
// 		Sig: sig,
// 	}
// 	witness := BLSSigGKRCircuit{
// 		Pub: pub,
// 		msg: msgBytes,
// 		Sig: sig,
// 	}
// 	err := test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
// 	assert.NoError(err)
// }

func TestBlsSigGKRTestSolve(t *testing.T) {

	msgHex := "5656565656565656565656565656565656565656565656565656565656565656"
	pubHex := "a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a"
	sigHex := "882730e5d03f6b42c3abc26d3372625034e1d871b65a8a6b900a56dae22da98abbe1b68f85e49fe7652a55ec3d0591c20767677e33e5cbb1207315c41a9ac03be39c2e7668edc043d6cb1d9fd93033caa8a1c5b0e84bedaeb6c64972503a43eb"

	msgBytes := make([]byte, len(msgHex)>>1)
	hex.Decode(msgBytes, []byte(msgHex))
	pubBytes := make([]byte, len(pubHex)>>1)
	hex.Decode(pubBytes, []byte(pubHex))
	sigBytes := make([]byte, len(sigHex)>>1)
	hex.Decode(sigBytes, []byte(sigHex))

	var pub bls12381.G1Affine
	_, e := pub.SetBytes(pubBytes)
	if e != nil {
		t.Fail()
	}
	var sig bls12381.G2Affine
	_, e = sig.SetBytes(sigBytes)
	if e != nil {
		t.Fail()
	}

	var g1GNeg bls12381.G1Affine
	_, _, g1Gen, _ := bls12381.Generators()
	g1GNeg.Neg(&g1Gen)

	h, e := bls12381.HashToG2(msgBytes, []byte(g2_dst))
	if e != nil {
		t.Fail()
	}

	b, e := bls12381.PairingCheck([]bls12381.G1Affine{g1GNeg, pub}, []bls12381.G2Affine{sig, h})
	if e != nil {
		t.Fail()
	}
	if !b {
		t.Fail() // invalid inputs, won't verify
	}

	blsCircuit := &BLSSigGKRCircuit{
		Pub: pub,
		msg: msgBytes,
		Sig: sig,
	}
	// BLS12-381 scalar field modulus
	circuit, err := ecgo.Compile(ecc.BN254.ScalarField(), blsCircuit)
	if err != nil {
		panic(err)
	}
	c := circuit.GetLayeredCircuit()
	os.WriteFile("circuit.txt", c.Serialize(), 0o644)
	assignment := &BLSSigGKRCircuit{
		Pub: pub,
		msg: msgBytes,
		Sig: sig,
	}
	inputSolver := circuit.GetInputSolver()
	witness, err := inputSolver.SolveInput(assignment, 8)
	if err != nil {
		panic(err)
	}

	if !test.CheckCircuit(c, witness) {
		panic("error")
	}

	os.WriteFile("inputsolver.txt", inputSolver.Serialize(), 0o644)
	os.WriteFile("circuit.txt", c.Serialize(), 0o644)
	os.WriteFile("witness.txt", witness.Serialize(), 0o644)

}
