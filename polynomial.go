package polynomial

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
)

// Circuit for the evaluation of polynomial P(X) = c_0 + c_1 * x + ... + c_n * x^n
// array Coefficient is encoded into circuit (is not a part of witness).
// InputVariables - x_1, x_2, ..., x_k
// OutputVariables - P(x_1), P(x_2), ..., P(x_k)

type PolynomialEval struct {
	InputVariables  []frontend.Variable `gnark:",public"`
	OutputVariables []frontend.Variable `gnark:",public"`
	Coefficients    []big.Int
}

func eval(p []big.Int, x frontend.Variable, api frontend.API) frontend.Variable {
	n := len(p)
	var res frontend.Variable
	res = p[n-1]
	for i := n - 2; i >= 0; i-- {
		res = api.Mul(res, x)
		res = api.Add(res, p[i])
	}
	return res
}

func (circuit *PolynomialEval) Define(api frontend.API) error {

	api.AssertIsEqual(len(circuit.InputVariables), len(circuit.OutputVariables))
	for i := 0; i < len(circuit.InputVariables); i++ {
		f := eval(circuit.Coefficients, circuit.InputVariables[i], api)
		api.AssertIsEqual(f, circuit.OutputVariables[i])
	}
	return nil
}
