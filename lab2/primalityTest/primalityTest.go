package primalityTest

import (
	"crypto/rand"
	"fmt"
	"lab2/statelessService"
	"math"
	"math/big"
)

type PrimalityTester interface {
	IsProbablyPrime(n *big.Int, minProbability float64) (bool, error)
	GetTestName() string
}

type SingleTestExecutor interface {
	ExecuteSingleTest(n *big.Int, candidate *big.Int) (bool, error)
}

type BasePrimalityTest struct {
	executor SingleTestExecutor
	testName string
}

func NewBasePrimalityTest(executor SingleTestExecutor, testName string) *BasePrimalityTest {
	return &BasePrimalityTest{
		executor: executor,
		testName: testName,
	}
}

func (b *BasePrimalityTest) IsProbablyPrime(n *big.Int, minProbability float64) (bool, error) {
	if n == nil || b == nil {
		return false, fmt.Errorf("IsProbablyPrime: arguments must not be nil")
	}

	if minProbability < 0.5 || minProbability >= 1.0 {
		return false, fmt.Errorf("IsProbablyPrime: minProbability must be [0.5, 1)")
	}

	if n.Cmp(big.NewInt(2)) < 0 {
		return false, nil
	}

	if n.Cmp(big.NewInt(2)) == 0 || n.Cmp(big.NewInt(3)) == 0 {
		return true, nil
	}

	if new(big.Int).Mod(n, big.NewInt(2)).Cmp(big.NewInt(0)) == 0 {
		return false, nil
	}

	k, err := b.calculateIterations(minProbability)
	if err != nil {
		return false, fmt.Errorf("IsProbablyPrime: %w", err)
	}

	for i := 0; i < k; i++ {
		candidate, err := b.generateCandidate(n)
		if err != nil {
			return false, fmt.Errorf("IsProbablyPrime: %w", err)
		}

		ok, err := b.executor.ExecuteSingleTest(n, candidate)
		if err != nil {
			return false, fmt.Errorf("IsProbablyPrime: %w", err)
		}

		if !ok {
			return false, nil
		}
	}

	return true, nil
}

func (b *BasePrimalityTest) GetTestName() string {
	return b.testName
}

func (b *BasePrimalityTest) calculateIterations(minProbability float64) (int, error) {
	if b == nil {
		return 0, fmt.Errorf("calculateIterations: arguments must not be nil")
	}

	if minProbability <= 0.5 {
		return 1, nil
	}

	errorProbability := 1.0 - minProbability
	k := math.Ceil(math.Log(errorProbability) / math.Log(0.5))
	result := int(math.Max(1, k))
	return result, nil
}

func (b *BasePrimalityTest) generateCandidate(n *big.Int) (*big.Int, error) {
	if n == nil || b == nil {
		return nil, fmt.Errorf("generateCandidate: arguments must not be nil")
	}

	if n.Cmp(big.NewInt(2)) < 0 {
		return nil, fmt.Errorf("generateCandidate: n must be at least 2")
	}

	limit := new(big.Int).Sub(n, big.NewInt(1))
	candidate, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("generateCandidate: %w", err)
	}

	candidate.Add(candidate, big.NewInt(1))

	return candidate, nil
}

type FermatTest struct {
	*BasePrimalityTest
}

func NewFermatTest() *FermatTest {
	ft := &FermatTest{}
	ft.BasePrimalityTest = NewBasePrimalityTest(ft, "Fermat Test")
	return ft
}

func (ft *FermatTest) ExecuteSingleTest(n *big.Int, a *big.Int) (bool, error) {
	if n == nil || a == nil || ft == nil {
		return false, fmt.Errorf("ExecuteSingleTest: arguments must not be nil")
	}

	exp := new(big.Int).Sub(n, big.NewInt(1))
	result, err := statelessService.ModPow(a, exp, n)
	if err != nil {
		return false, fmt.Errorf("ExecuteSingleTest: %w", err)
	}

	return result.Cmp(big.NewInt(1)) == 0, nil
}

type SolovayStrassenTest struct {
	*BasePrimalityTest
}

func NewSolovayStrassenTest() *SolovayStrassenTest {
	sst := &SolovayStrassenTest{}
	sst.BasePrimalityTest = NewBasePrimalityTest(sst, "Solovay-Strassen Test")
	return sst
}

func (sst *SolovayStrassenTest) ExecuteSingleTest(n *big.Int, a *big.Int) (bool, error) {
	if n == nil || a == nil || sst == nil {
		return false, fmt.Errorf("ExecuteSingleTest: arguments must not be nil")
	}

	jacobiSymbol, err := statelessService.Jacobi(a, n)
	if err != nil {
		return false, fmt.Errorf("ExecuteSingleTest: %w", err)
	}

	if jacobiSymbol == 0 {
		return false, nil
	}

	exp := new(big.Int).Sub(n, big.NewInt(1))
	exp.Div(exp, big.NewInt(2))
	result, err := statelessService.ModPow(a, exp, n)
	if err != nil {
		return false, fmt.Errorf("ExecuteSingleTest: %w", err)
	}

	var jacobiMod *big.Int
	if jacobiSymbol == 1 {
		jacobiMod = big.NewInt(1)
	} else {
		jacobiMod = new(big.Int).Sub(n, big.NewInt(1))
	}

	return result.Cmp(jacobiMod) == 0, nil
}

type MillerRabinTest struct {
	*BasePrimalityTest
}

func NewMillerRabinTest() *MillerRabinTest {
	mrt := &MillerRabinTest{}
	mrt.BasePrimalityTest = NewBasePrimalityTest(mrt, "Miller-Rabin Test")
	return mrt
}

func (mrt *MillerRabinTest) ExecuteSingleTest(n *big.Int, a *big.Int) (bool, error) {
	if n == nil || a == nil || mrt == nil {
		return false, fmt.Errorf("ExecuteSingleTest: arguments must not be nil")
	}

	nMinus1 := new(big.Int).Sub(n, big.NewInt(1))
	s := 0
	d := new(big.Int).Set(nMinus1)

	for new(big.Int).Mod(d, big.NewInt(2)).Cmp(big.NewInt(0)) == 0 {
		s++
		d.Div(d, big.NewInt(2))
	}

	x, err := statelessService.ModPow(a, d, n)
	if err != nil {
		return false, fmt.Errorf("ExecuteSingleTest: %w", err)
	}

	if x.Cmp(big.NewInt(1)) == 0 {
		return true, nil
	}

	nMinus1Copy := new(big.Int).Set(nMinus1)
	if x.Cmp(nMinus1Copy) == 0 {
		return true, nil
	}

	for r := 1; r < s; r++ {
		x.Mul(x, x)
		x.Mod(x, n)

		if x.Cmp(nMinus1Copy) == 0 {
			return true, nil
		}
	}

	return false, nil
}
