package main

import (
	"encoding/hex"
	"math/big"
	"os"

	"github.com/PolyhedraZK/ExpanderCompilerCollection/ecgo/test"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/fields_bls12381"
	sw_bls12381 "github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/math/emulated"

	"github.com/PolyhedraZK/ExpanderCompilerCollection/ecgo"
	// "github.com/consensys/gnark-crypto/ecc"
	"github.com/PolyhedraZK/ExpanderCompilerCollection/ecgo/field/bn254"
)

const g2_dst = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"

type BLSSigGKRCircuit struct {
	Pub [2]frontend.Variable
	Msg [32]frontend.Variable
	Sig [4]frontend.Variable
}

func (c *BLSSigGKRCircuit) Define(api frontend.API) error {
	var g1GNeg bls12381.G1Affine
	_, _, g1Gen, _ := bls12381.Generators()
	g1GNeg.Neg(&g1Gen)
	g1GN := sw_bls12381.NewG1Affine(g1GNeg)

	msgBytes := make([]byte, len(c.Msg))
	for i := 0; i < len(c.Msg); i++ {
		if v, ok := c.Msg[i].(uint64); ok {
			msgBytes[i] = byte(v)
		}
	}

	h, err := bls12381.HashToG2(msgBytes, []byte(g2_dst))
	if err != nil {
		return err
	}
	h_sw := sw_bls12381.NewG2Affine(h)
	field, err := emulated.NewField[sw_bls12381.BaseField](api)
	if err != nil {
		return err
	}

	// Create field elements for public key coordinates
	x := field.NewElement(&emulated.Element[sw_bls12381.BaseField]{Limbs: []frontend.Variable{c.Pub[0]}})
	y := field.NewElement(&emulated.Element[sw_bls12381.BaseField]{Limbs: []frontend.Variable{c.Pub[1]}})

	pubPoint := sw_bls12381.G1Affine{
		X: *x,
		Y: *y,
	}

	// Create field elements for signature coordinates
	x0 := field.NewElement(&emulated.Element[sw_bls12381.BaseField]{Limbs: []frontend.Variable{c.Sig[0]}})
	x1 := field.NewElement(&emulated.Element[sw_bls12381.BaseField]{Limbs: []frontend.Variable{c.Sig[1]}})
	y0 := field.NewElement(&emulated.Element[sw_bls12381.BaseField]{Limbs: []frontend.Variable{c.Sig[2]}})
	y1 := field.NewElement(&emulated.Element[sw_bls12381.BaseField]{Limbs: []frontend.Variable{c.Sig[3]}})

	sigPoint := sw_bls12381.G2Affine{
		P: struct {
			X, Y fields_bls12381.E2
		}{
			X: fields_bls12381.E2{
				A0: *x0,
				A1: *x1,
			},
			Y: fields_bls12381.E2{
				A0: *y0,
				A1: *y1,
			},
		},
	}

	pairing, err := sw_bls12381.NewPairing(api)
	if err != nil {
		return err
	}
	error := pairing.PairingCheck([]*sw_bls12381.G1Affine{&g1GN, &pubPoint}, []*sw_bls12381.G2Affine{&sigPoint, &h_sw})
	if error != nil {
		return error
	}
	return nil
}

func main() {
	// Test parameters
	msgHex := "5656565656565656565656565656565656565656565656565656565656565656"
	pubHex := "a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a"
	sigHex := "882730e5d03f6b42c3abc26d3372625034e1d871b65a8a6b900a56dae22da98abbe1b68f85e49fe7652a55ec3d0591c20767677e33e5cbb1207315c41a9ac03be39c2e7668edc043d6cb1d9fd93033caa8a1c5b0e84bedaeb6c64972503a43eb"

	// Decode message
	msgBytes, err := hex.DecodeString(msgHex)
	if err != nil {
		panic(err)
	}

	// Decode public key
	pubBytes, err := hex.DecodeString(pubHex)
	if err != nil {
		panic(err)
	}
	var pubKey bls12381.G1Affine
	_, err = pubKey.SetBytes(pubBytes)
	if err != nil {
		panic(err)
	}

	// Decode signature
	sigBytes, err := hex.DecodeString(sigHex)
	if err != nil {
		panic(err)
	}
	var sig bls12381.G2Affine
	_, err = sig.SetBytes(sigBytes)
	if err != nil {
		panic(err)
	}

	// Create the circuit
	circuit, err := ecgo.Compile(bn254.ScalarField, &BLSSigGKRCircuit{})
	if err != nil {
		panic(err)
	}

	c := circuit.GetLayeredCircuit()
	os.WriteFile("circuit.txt", c.Serialize(), 0o644)

	// Create assignment
	assignment := &BLSSigGKRCircuit{
		Pub: [2]frontend.Variable{
			new(big.Int).Mod(pubKey.X.BigInt(new(big.Int)), bn254.ScalarField).Uint64(),
			new(big.Int).Mod(pubKey.Y.BigInt(new(big.Int)), bn254.ScalarField).Uint64(),
		},
		Msg: [32]frontend.Variable{},
		Sig: [4]frontend.Variable{
			new(big.Int).Mod(sig.X.A0.BigInt(new(big.Int)), bn254.ScalarField).Uint64(),
			new(big.Int).Mod(sig.X.A1.BigInt(new(big.Int)), bn254.ScalarField).Uint64(),
			new(big.Int).Mod(sig.Y.A0.BigInt(new(big.Int)), bn254.ScalarField).Uint64(),
			new(big.Int).Mod(sig.Y.A1.BigInt(new(big.Int)), bn254.ScalarField).Uint64(),
		},
	}

	// Fill the message bytes
	for i := 0; i < 32; i++ {
		assignment.Msg[i] = msgBytes[i]
	}

	// Solve input and check circuit
	inputSolver := circuit.GetInputSolver()
	witness, err := inputSolver.SolveInput(assignment, 8)
	if err != nil {
		panic(err)
	}

	if !test.CheckCircuit(c, witness) {
		panic("Circuit check failed")
	}

	// Write output files
	os.WriteFile("inputsolver.txt", inputSolver.Serialize(), 0o644)
	os.WriteFile("circuit.txt", c.Serialize(), 0o644)
	os.WriteFile("witness.txt", witness.Serialize(), 0o644)
}
