package main

import (
	"encoding/hex"
	"math/big"
	"os"

	"github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/fields_bls12381"
	sw_bls12381 "github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/math/emulated"

	"github.com/PolyhedraZK/ExpanderCompilerCollection/ecgo"
	"github.com/PolyhedraZK/ExpanderCompilerCollection/ecgo/field/bn254"
	"github.com/PolyhedraZK/ExpanderCompilerCollection/ecgo/test"
)

type BLSSigGKRCircuit struct {
	Pub [2]frontend.Variable
	Msg [32]frontend.Variable
	Sig [4]frontend.Variable
}

const g2_dst = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"

func (c *BLSSigGKRCircuit) Define(api frontend.API) error {
	var g1GNeg bls12381.G1Affine
	_, _, g1Gen, _ := bls12381.Generators()
	g1GNeg.Neg(&g1Gen)
	g1GN := sw_bls12381.NewG1Affine(g1GNeg)

	// Convert message to bytes and create hash point
	msgBytes := make([]byte, 32)
	for i := 0; i < 32; i++ {
		msgBytes[i] = 0x56 // Fixed test message byte
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

	// Create public key point
	pubPoint := sw_bls12381.G1Affine{
		X: *field.NewElement(c.Pub[0]),
		Y: *field.NewElement(c.Pub[1]),
	}

	// Create signature point
	sigPoint := sw_bls12381.G2Affine{
		P: struct {
			X, Y fields_bls12381.E2
		}{
			X: fields_bls12381.E2{
				A0: *field.NewElement(c.Sig[0]),
				A1: *field.NewElement(c.Sig[1]),
			},
			Y: fields_bls12381.E2{
				A0: *field.NewElement(c.Sig[2]),
				A1: *field.NewElement(c.Sig[3]),
			},
		},
	}

	// Verify pairing
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

	// Convert coordinates to small field elements
	m31ModInt := new(big.Int).SetUint64(uint64(1) << 31)
	m31ModInt.Sub(m31ModInt, big.NewInt(1))

	// Split each coordinate into smaller chunks that fit in m31
	chunks := func(b [48]byte) []uint64 {
		result := make([]uint64, 0)
		bigInt := new(big.Int).SetBytes(b[:])
		temp := new(big.Int)
		for bigInt.BitLen() > 0 {
			temp.And(bigInt, m31ModInt)
			result = append(result, temp.Uint64())
			bigInt.Rsh(bigInt, 31)
		}
		return result
	}

	// Get chunks for each coordinate
	pubXBytes := pubKey.X.Bytes()
	pubYBytes := pubKey.Y.Bytes()
	sigX0Bytes := sig.X.A0.Bytes()
	sigX1Bytes := sig.X.A1.Bytes()
	sigY0Bytes := sig.Y.A0.Bytes()
	sigY1Bytes := sig.Y.A1.Bytes()

	pubXChunks := chunks(pubXBytes)
	pubYChunks := chunks(pubYBytes)
	sigX0Chunks := chunks(sigX0Bytes)
	sigX1Chunks := chunks(sigX1Bytes)
	sigY0Chunks := chunks(sigY0Bytes)
	sigY1Chunks := chunks(sigY1Bytes)

	// Create assignment using first chunk of each coordinate
	assignment := &BLSSigGKRCircuit{
		Pub: [2]frontend.Variable{pubXChunks[0], pubYChunks[0]},
		Msg: [32]frontend.Variable{},
		Sig: [4]frontend.Variable{
			sigX0Chunks[0], sigX1Chunks[0],
			sigY0Chunks[0], sigY1Chunks[0],
		},
	}

	// Fill the message bytes
	for i := 0; i < 32; i++ {
		assignment.Msg[i] = uint64(msgBytes[i]) % ((1 << 31) - 1)
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
