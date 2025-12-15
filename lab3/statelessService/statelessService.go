package statelessService

import (
	"fmt"
)

type GF28Service struct{}

func NewGF28Service() *GF28Service {
	return &GF28Service{}
}

func (g *GF28Service) Add(a, b byte) (byte, error) {
	if g == nil {
		return 0, fmt.Errorf("Add: service must not be nil")
	}
	return a ^ b, nil
}

func (g *GF28Service) Multiply(a, b, modulus byte) (byte, error) {
	if g == nil {
		return 0, fmt.Errorf("Multiply: service must not be nil")
	}

	isIrreducible, err := g.IsIrreducibleDegree8(uint16(modulus) | 0x100)
	if err != nil {
		return 0, fmt.Errorf("Multiply: %w", err)
	}
	if !isIrreducible {
		return 0, fmt.Errorf("Multiply: modulus 0x%02X is not irreducible", modulus)
	}

	result := byte(0)
	tempA := a
	tempB := b

	for i := 0; i < 8; i++ {
		if (tempB & 1) != 0 {
			result ^= tempA
		}

		highBitSet := (tempA & 0x80) != 0

		tempA <<= 1

		if highBitSet {
			tempA ^= modulus
		}

		tempB >>= 1
	}

	return result, nil
}

func (g *GF28Service) Inverse(a, modulus byte) (byte, error) {
	if g == nil {
		return 0, fmt.Errorf("Inverse: service must not be nil")
	}

	if a == 0 {
		return 0, fmt.Errorf("Inverse: zero has no inverse")
	}

	isIrreducible, err := g.IsIrreducibleDegree8(uint16(modulus) | 0x100)
	if err != nil {
		return 0, fmt.Errorf("Inverse: %w", err)
	}
	if !isIrreducible {
		return 0, fmt.Errorf("Inverse: modulus 0x%02X is not irreducible", modulus)
	}

	r0 := uint16(modulus) | 0x100
	r1 := uint16(a)
	t0 := uint16(0)
	t1 := uint16(1)

	for r1 != 0 {
		q, err := g.polyDiv(r0, r1)
		if err != nil {
			return 0, fmt.Errorf("Inverse: %w", err)
		}

		r2, err := g.polyMod(r0, r1)
		if err != nil {
			return 0, fmt.Errorf("Inverse: %w", err)
		}

		t2 := t0 ^ g.polyMultiply(q, t1)

		r0 = r1
		r1 = r2
		t0 = t1
		t1 = t2
	}

	if r0 != 1 {
		return 0, fmt.Errorf("Inverse: element 0x%02X is not invertible modulo 0x%02X", a, modulus)
	}

	return byte(t0 & 0xFF), nil
}

func (g *GF28Service) IsIrreducible(poly uint16) (bool, error) {
	if g == nil {
		return false, fmt.Errorf("IsIrreducible: service must not be nil")
	}

	if poly == 0 {
		return false, fmt.Errorf("IsIrreducible: polynomial must not be zero")
	}

	degree := g.polyDegree(poly)

	if degree <= 0 {
		return false, nil
	}

	if (poly & 1) == 0 {
		return false, nil
	}

	if degree == 1 {
		return poly == 0x3, nil
	}

	maxDivisorDegree := degree / 2

	for divisor := uint16(0x3); g.polyDegree(divisor) <= maxDivisorDegree; divisor += 2 {
		if (divisor & 1) == 0 {
			continue
		}

		divisorIrreducible, err := g.IsIrreducible(divisor)
		if err != nil {
			return false, fmt.Errorf("IsIrreducible: %w", err)
		}

		if divisorIrreducible {
			remainder, err := g.polyMod(poly, divisor)
			if err != nil {
				return false, fmt.Errorf("IsIrreducible: %w", err)
			}
			if remainder == 0 {
				return false, nil
			}
		}
	}

	return true, nil
}

func (g *GF28Service) IsIrreducibleDegree8(poly uint16) (bool, error) {
	if g == nil {
		return false, fmt.Errorf("IsIrreducibleDegree8: service must not be nil")
	}

	if poly < 0x100 || poly > 0x1FF {
		return false, fmt.Errorf("IsIrreducibleDegree8: polynomial 0x%03X must be of degree 8", poly)
	}

	return g.IsIrreducible(poly)
}

func (g *GF28Service) ListIrreduciblePolynomials() ([]uint16, error) {
	if g == nil {
		return nil, fmt.Errorf("ListIrreduciblePolynomials: service must not be nil")
	}

	result := make([]uint16, 0, 30)

	for poly := uint16(0x101); poly < 0x200; poly += 2 {
		isIrr, err := g.IsIrreducible(poly)
		if err != nil {
			return nil, fmt.Errorf("ListIrreduciblePolynomials: %w", err)
		}
		if isIrr {
			result = append(result, poly)
		}
	}

	return result, nil
}

func (g *GF28Service) Factorize(poly uint16) ([]uint16, error) {
	if g == nil {
		return nil, fmt.Errorf("Factorize: service must not be nil")
	}

	if poly == 0 {
		return nil, fmt.Errorf("Factorize: cannot factorize zero polynomial")
	}

	factors := make([]uint16, 0)
	current := poly

	for divisor := uint16(0x3); divisor <= current && current > 1; {
		isIrr, err := g.IsIrreducible(divisor)
		if err != nil {
			return nil, fmt.Errorf("Factorize: %w", err)
		}

		if isIrr {
			remainder, err := g.polyMod(current, divisor)
			if err != nil {
				return nil, fmt.Errorf("Factorize: %w", err)
			}

			if remainder == 0 {
				factors = append(factors, divisor)
				quotient, err := g.polyDiv(current, divisor)
				if err != nil {
					return nil, fmt.Errorf("Factorize: %w", err)
				}
				current = quotient
				continue
			}
		}

		if divisor == 0x3 {
			divisor = 0x7
		} else {
			divisor += 2
		}
	}

	if current > 1 {
		factors = append(factors, current)
	}

	return factors, nil
}

func (g *GF28Service) polyDegree(poly uint16) int {
	if poly == 0 {
		return -1
	}
	degree := 0
	temp := poly
	for temp > 1 {
		temp >>= 1
		degree++
	}
	return degree
}

func (g *GF28Service) polyMod(a, b uint16) (uint16, error) {
	if b == 0 {
		return 0, fmt.Errorf("polyMod: division by zero")
	}

	remainder := a
	divisorDegree := g.polyDegree(b)

	for {
		remainderDegree := g.polyDegree(remainder)
		if remainderDegree < divisorDegree {
			break
		}

		shift := remainderDegree - divisorDegree
		remainder ^= (b << shift)
	}

	return remainder, nil
}

func (g *GF28Service) polyDiv(a, b uint16) (uint16, error) {
	if b == 0 {
		return 0, fmt.Errorf("polyDiv: division by zero")
	}

	quotient := uint16(0)
	remainder := a
	divisorDegree := g.polyDegree(b)

	for {
		remainderDegree := g.polyDegree(remainder)
		if remainderDegree < divisorDegree {
			break
		}

		shift := remainderDegree - divisorDegree
		quotient |= (1 << shift)
		remainder ^= (b << shift)
	}

	return quotient, nil
}

func (g *GF28Service) polyMultiply(a, b uint16) uint16 {
	result := uint16(0)
	tempA := a

	for i := 0; i < 16; i++ {
		if (b & (1 << i)) != 0 {
			result ^= (tempA << i)
		}
	}

	return result
}
