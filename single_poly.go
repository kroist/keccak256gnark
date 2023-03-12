package polynomial

import (
	"github.com/consensys/gnark/frontend"
)

// Circuit of polynomial
// P(x) = 1+x

type SinglePoly struct {
	InputVariable  frontend.Variable
	OutputVariable frontend.Variable `gnark:",public"`
}

func (circuit *SinglePoly) Define(api frontend.API) error {
	f := api.Add(1, circuit.InputVariable)
	api.AssertIsEqual(f, circuit.OutputVariable)
	return nil
}
