package polynomial

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

func TestPolynomialEval(t *testing.T) {
	assert := test.NewAssert(t)

	// P(x) = 1 + x, x = 1, y = 2

	var polynomialEval PolynomialEval
	polynomialEval.InputVariables = make([]frontend.Variable, 1)
	polynomialEval.OutputVariables = make([]frontend.Variable, 1)
	polynomialEval.InputVariables[0] = 0
	polynomialEval.OutputVariables[0] = 0
	polynomialEval.Coefficients = make([]big.Int, 2)
	polynomialEval.Coefficients[0] = *big.NewInt(1)
	polynomialEval.Coefficients[1] = *big.NewInt(1)

	var witness PolynomialEval
	witness.InputVariables = make([]frontend.Variable, 1)
	witness.OutputVariables = make([]frontend.Variable, 1)

	witness.InputVariables[0] = 1
	witness.OutputVariables[0] = 2
	assert.ProverSucceeded(&polynomialEval, &witness)
}
