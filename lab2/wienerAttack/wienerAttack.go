package wienerAttack

import (
	"fmt"
	"lab2/statelessService"
	"math/big"
)

type Convergent struct {
	Numerator   *big.Int
	Denominator *big.Int
	Index       int
}

func (c Convergent) String() string {
	return fmt.Sprintf("[%d] %s/%s", c.Index, c.Numerator.String(), c.Denominator.String())
}

type WienerResult struct {
	Success     bool
	D           *big.Int
	Phi         *big.Int
	P           *big.Int
	Q           *big.Int
	Convergents []Convergent
	Message     string
}

type WienerAttackService struct{}

func NewWienerAttackService() *WienerAttackService {
	return &WienerAttackService{}
}

func (was *WienerAttackService) Attack(e, N *big.Int) (*WienerResult, error) {
	if e == nil || N == nil || was == nil {
		return nil, fmt.Errorf("Attack: arguments must not be nil")
	}

	if e.Sign() <= 0 || N.Sign() <= 0 {
		return nil, fmt.Errorf("e and N must be positive")
	}

	if e.Cmp(N) >= 0 {
		return nil, fmt.Errorf("e must be < N")
	}

	cfExpansion, err := was.continuedFractionExpansion(e, N)
	if err != nil {
		return nil, fmt.Errorf("Attack: %w", err)
	}

	convergents, err := was.computeConvergents(cfExpansion)
	if err != nil {
		return nil, fmt.Errorf("Attack: %w", err)
	}

	for _, conv := range convergents {
		k := conv.Numerator
		d := conv.Denominator

		if k.Sign() == 0 || d.Sign() == 0 {
			continue
		}

		phi, p, q, valid, err := was.checkCandidate(e, N, k, d)
		if err != nil {
			return nil, fmt.Errorf("Attack: %w", err)
		}

		if valid {
			return &WienerResult{
				Success:     true,
				D:           d,
				Phi:         phi,
				P:           p,
				Q:           q,
				Convergents: convergents,
				Message:     fmt.Sprintf("Attack successful! Found private exponent d in the %d-th convergent", conv.Index),
			}, nil
		}
	}

	return &WienerResult{
		Success:     false,
		D:           nil,
		Phi:         nil,
		P:           nil,
		Q:           nil,
		Convergents: convergents,
		Message:     "Wiener attack failed. The key is probably not vulnerable (d is too large)",
	}, nil
}

func (was *WienerAttackService) continuedFractionExpansion(e, N *big.Int) ([]*big.Int, error) {
	if e == nil || N == nil || was == nil {
		return nil, fmt.Errorf("continuedFractionExpansion: arguments must not be nil")
	}

	var cfExpansion []*big.Int

	num := new(big.Int).Set(e)
	den := new(big.Int).Set(N)
	maxIterations := 10000

	for i := 0; i < maxIterations && den.Sign() > 0; i++ {
		quotient := new(big.Int).Div(num, den)
		cfExpansion = append(cfExpansion, quotient)
		remainder := new(big.Int).Mod(num, den)
		num.Set(den)
		den.Set(remainder)
	}

	return cfExpansion, nil
}

func (was *WienerAttackService) computeConvergents(cfExpansion []*big.Int) ([]Convergent, error) {
	if was == nil || cfExpansion == nil {
		return nil, fmt.Errorf("computeConvergents: arguments must not be nil")
	}

	if len(cfExpansion) == 0 {
		return nil, fmt.Errorf("len(cfExpansion) mus be > 0")
	}

	var convergents []Convergent

	pPrev2 := big.NewInt(1)
	pPrev1 := new(big.Int).Set(cfExpansion[0])

	qPrev2 := big.NewInt(0)
	qPrev1 := big.NewInt(1)

	convergents = append(convergents, Convergent{
		Numerator:   new(big.Int).Set(pPrev1),
		Denominator: new(big.Int).Set(qPrev1),
		Index:       0,
	})

	for i := 1; i < len(cfExpansion); i++ {
		a := cfExpansion[i]

		pCurr := new(big.Int).Mul(a, pPrev1)
		pCurr.Add(pCurr, pPrev2)

		qCurr := new(big.Int).Mul(a, qPrev1)
		qCurr.Add(qCurr, qPrev2)

		convergents = append(convergents, Convergent{
			Numerator:   new(big.Int).Set(pCurr),
			Denominator: new(big.Int).Set(qCurr),
			Index:       i,
		})

		pPrev2.Set(pPrev1)
		pPrev1.Set(pCurr)
		qPrev2.Set(qPrev1)
		qPrev1.Set(qCurr)
	}

	return convergents, nil
}

func (was *WienerAttackService) checkCandidate(e, N, k, d *big.Int) (*big.Int, *big.Int, *big.Int, bool, error) {
	if was == nil || e == nil || N == nil || k == nil || d == nil {
		return nil, nil, nil, false, fmt.Errorf("checkCandidate: arguments must not be nil")
	}

	ed := new(big.Int).Mul(e, d)
	edMinus1 := new(big.Int).Sub(ed, big.NewInt(1))

	if k.Sign() == 0 {
		return nil, nil, nil, false, nil
	}

	if new(big.Int).Mod(edMinus1, k).Cmp(big.NewInt(0)) != 0 {
		return nil, nil, nil, false, nil
	}

	phi := new(big.Int).Div(edMinus1, k)

	if phi.Sign() <= 0 || phi.Cmp(N) >= 0 {
		return nil, nil, nil, false, nil
	}

	gcd, err := statelessService.GCD(e, phi)
	if err != nil {
		return nil, nil, nil, false, fmt.Errorf("GCD error: %w", err)
	}
	if gcd.Cmp(big.NewInt(1)) != 0 {
		return nil, nil, nil, false, nil
	}

	sum := new(big.Int).Sub(N, phi)
	sum.Add(sum, big.NewInt(1))

	sumSquared := new(big.Int).Mul(sum, sum)
	fourN := new(big.Int).Lsh(N, 2)
	discriminant := new(big.Int).Sub(sumSquared, fourN)

	if discriminant.Sign() < 0 {
		return nil, nil, nil, false, nil
	}

	sqrtDisc := new(big.Int).Sqrt(discriminant)
	if new(big.Int).Mul(sqrtDisc, sqrtDisc).Cmp(discriminant) != 0 {
		return nil, nil, nil, false, nil
	}

	p := new(big.Int).Add(sum, sqrtDisc)
	if new(big.Int).Mod(p, big.NewInt(2)).Cmp(big.NewInt(0)) != 0 {
		return nil, nil, nil, false, nil
	}
	p.Div(p, big.NewInt(2))

	q := new(big.Int).Sub(sum, sqrtDisc)
	if new(big.Int).Mod(q, big.NewInt(2)).Cmp(big.NewInt(0)) != 0 {
		return nil, nil, nil, false, nil
	}
	q.Div(q, big.NewInt(2))

	product := new(big.Int).Mul(p, q)
	if product.Cmp(N) != 0 {
		return nil, nil, nil, false, nil
	}

	testMsg := big.NewInt(42)
	if testMsg.Cmp(N) >= 0 {
		return phi, p, q, true, nil
	}

	encrypted, err := statelessService.ModPow(testMsg, e, N)
	if err != nil {
		return nil, nil, nil, false, fmt.Errorf("encryption test failed: %w", err)
	}

	decrypted, err := statelessService.ModPow(encrypted, d, N)
	if err != nil {
		return nil, nil, nil, false, fmt.Errorf("decryption test failed: %w", err)
	}

	if decrypted.Cmp(testMsg) != 0 {
		return nil, nil, nil, false, nil
	}

	return phi, p, q, true, nil
}
