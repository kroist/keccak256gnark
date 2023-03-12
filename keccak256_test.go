package polynomial

import (
	"encoding/hex"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

func TestKeccakEval(t *testing.T) {
	testCorrect(
		t,
		[]byte{},
		strToBytes(t, "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"),
	)
	testCorrect(
		t,
		[]byte("test"),
		strToBytes(t, "9c22ff5f21f0b81b113e63f7db6da94fedef11b2119b4088b89664fb9a3cb658"),
	)
}

func initCircuit(t *testing.T, inLen int) Keccak256 {
	var k256 Keccak256
	k256.InputVariables = make([]frontend.Variable, inLen)
	k256.OutputVariables = make([]frontend.Variable, 256)
	for i := 0; i < inLen; i++ {
		k256.InputVariables[i] = 0
	}
	for i := 0; i < 256; i++ {
		k256.OutputVariables[i] = 0
	}

	return k256
}

func testCorrect(t *testing.T, input []byte, output []byte) {
	assert := test.NewAssert(t)

	bitI := bytesToBits(t, input)
	bitO := bytesToBits(t, output)
	assert.Equal(len(bitO), 256)

	circuit := initCircuit(t, len(bitI))
	witness := initCircuit(t, len(bitI))
	for i := 0; i < len(bitI); i++ {
		witness.InputVariables[i] = bitI[i]
	}
	for i := 0; i < 256; i++ {
		witness.OutputVariables[i] = bitO[i]
	}

	// test circuit for eval without proving
	err := test.IsSolved(&circuit, &witness, ecc.BN254, backend.PLONK)
	if err != nil {
		t.Fatal(err)
	}

	assert.ProverSucceeded(&circuit, &witness, test.WithBackends(backend.PLONK), test.WithCurves(ecc.BN254))
}

func strToBytes(t *testing.T, input string) []byte {
	data, err := hex.DecodeString(input)
	if err != nil {
		panic(err)
	}
	return data
}

func bytesToBits(t *testing.T, input []byte) []uint8 {
	var res []uint8
	for i := 0; i < len(input); i++ {
		for j := 0; j < 8; j++ {
			res = append(res, (input[i]>>j)&1)
		}
	}
	return res
}
