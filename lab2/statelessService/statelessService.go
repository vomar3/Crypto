package statelessService

import (
	"fmt"
	"math/big"
)

func GCD(a, b *big.Int) (*big.Int, error) {
	if a == nil || b == nil {
		return nil, fmt.Errorf("GCD: arguments must not be nil")
	}

	x := new(big.Int).Abs(a)
	y := new(big.Int).Abs(b)
	temp := new(big.Int)

	for y.Sign() != 0 {
		temp.Set(y)
		y.Mod(x, y)
		x.Set(temp)
	}

	return x, nil
}

func ExtendedGCD(a, b *big.Int) (gcd, x, y *big.Int, err error) {
	if a == nil || b == nil {
		return nil, nil, nil, fmt.Errorf("ExtendedGCD: arguments must not be nil")
	}

	if b.Sign() == 0 {
		return new(big.Int).Set(a), big.NewInt(1), big.NewInt(0), nil
	}

	mod := new(big.Int).Mod(a, b)
	gcd1, x1, y1, err := ExtendedGCD(b, mod)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("ExtendedGCD: %w", err)
	}

	x = new(big.Int).Set(y1)
	div := new(big.Int).Div(a, b)
	y = new(big.Int).Mul(div, y1)
	y.Sub(x1, y)

	return gcd1, x, y, nil
}

func ModPow(base, exponent, modulus *big.Int) (*big.Int, error) {
	if base == nil || exponent == nil || modulus == nil {
		return nil, fmt.Errorf("ModPow: arguments must not be nil")
	}

	if modulus.Sign() <= 0 {
		return nil, fmt.Errorf("ModPow: modulus must be positive")
	}

	if modulus.Cmp(big.NewInt(1)) == 0 {
		return big.NewInt(0), nil
	}

	result := big.NewInt(1)
	base = new(big.Int).Mod(base, modulus)
	exp := new(big.Int).Set(exponent)

	zero := big.NewInt(0)
	two := big.NewInt(2)

	for exp.Cmp(zero) > 0 {
		if new(big.Int).Mod(exp, two).Cmp(big.NewInt(1)) == 0 {
			result.Mul(result, base)
			result.Mod(result, modulus)
		}

		exp.Div(exp, two)
		base.Mul(base, base)
		base.Mod(base, modulus)
	}

	return result, nil
}

func Legendre(a, p *big.Int) (int, error) {
	if a == nil || p == nil {
		return 0, fmt.Errorf("Legendre: arguments must not be nil")
	}

	if p.Cmp(big.NewInt(2)) <= 0 {
		return 0, fmt.Errorf("Legendre: p must be an odd prime greater than 2")
	}

	if new(big.Int).Mod(p, big.NewInt(2)).Sign() == 0 {
		return 0, fmt.Errorf("Legendre: p must be an odd prime, got even number")
	}

	if new(big.Int).Mod(a, p).Sign() == 0 {
		return 0, nil
	}

	exp := new(big.Int).Sub(p, big.NewInt(1))
	exp.Div(exp, big.NewInt(2))

	result, err := ModPow(a, exp, p)
	if err != nil {
		return 0, fmt.Errorf("Legendre: %w", err)
	}

	if result.Cmp(big.NewInt(1)) == 0 {
		return 1, nil
	}

	pMinus1 := new(big.Int).Sub(p, big.NewInt(1))
	if result.Cmp(pMinus1) == 0 {
		return -1, nil
	}

	return 0, fmt.Errorf("Legendre: result not in {1, p-1} for prime p")
}

func Jacobi(a, n *big.Int) (int, error) {
	if a == nil || n == nil {
		return 0, fmt.Errorf("Jacobi: arguments must not be nil")
	}

	a = new(big.Int).Set(a)
	n = new(big.Int).Set(n)

	if n.Sign() <= 0 || new(big.Int).Mod(n, big.NewInt(2)).Sign() == 0 {
		return 0, fmt.Errorf("Jacobi: n must be a positive odd integer")
	}

	a.Mod(a, n)
	result := 1

	zero := big.NewInt(0)
	one := big.NewInt(1)
	two := big.NewInt(2)
	eight := big.NewInt(8)

	for a.Cmp(zero) != 0 {
		for new(big.Int).Mod(a, two).Cmp(zero) == 0 {
			a.Div(a, two)
			nMod8 := new(big.Int).Mod(n, eight)
			if nMod8.Cmp(big.NewInt(3)) == 0 || nMod8.Cmp(big.NewInt(5)) == 0 {
				result = -result
			}
		}

		a, n = n, a

		if new(big.Int).Mod(a, big.NewInt(4)).Cmp(big.NewInt(3)) == 0 &&
			new(big.Int).Mod(n, big.NewInt(4)).Cmp(big.NewInt(3)) == 0 {
			result = -result
		}

		a.Mod(a, n)
	}

	if n.Cmp(one) == 0 {
		return result, nil
	}

	return 0, nil
}
