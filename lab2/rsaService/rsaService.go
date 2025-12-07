package rsaService

import (
	"crypto/rand"
	"fmt"
	"lab2/primalityTest"
	"lab2/statelessService"
	"math/big"
)

type PrimalityTestType int

const (
	Fermat PrimalityTestType = iota
	SolovayStrassen
	MillerRabin
)

func (p PrimalityTestType) String() string {
	switch p {
	case Fermat:
		return "Fermat"
	case SolovayStrassen:
		return "SolovayStrassen"
	case MillerRabin:
		return "MillerRabin"
	default:
		return "Unknown"
	}
}

type KeyGenerator struct {
	testType        PrimalityTestType
	minProbability  float64
	bitLength       int
	primalityTester primalityTest.PrimalityTester
}

type RSAKeyPair struct {
	PublicKey  *RSAPublicKey
	PrivateKey *RSAPrivateKey
	P, Q       *big.Int
}

type RSAPublicKey struct {
	N *big.Int
	E *big.Int
}

type RSAPrivateKey struct {
	N *big.Int
	D *big.Int
}

func NewKeyGenerator(testType PrimalityTestType, minProbability float64, bitLength int) (*KeyGenerator, error) {
	if minProbability < 0.5 || minProbability >= 1.0 {
		return nil, fmt.Errorf("minProbability must be [0.5, 1)")
	}

	if bitLength < 512 {
		return nil, fmt.Errorf("bitLength must be >= 512")
	}

	var tester primalityTest.PrimalityTester
	switch testType {
	case Fermat:
		tester = primalityTest.NewFermatTest()
	case SolovayStrassen:
		tester = primalityTest.NewSolovayStrassenTest()
	case MillerRabin:
		tester = primalityTest.NewMillerRabinTest()
	default:
		return nil, fmt.Errorf("unknown type")
	}

	return &KeyGenerator{
		testType:        testType,
		minProbability:  minProbability,
		bitLength:       bitLength,
		primalityTester: tester,
	}, nil
}

func (kg *KeyGenerator) GenerateKeyPair() (*RSAKeyPair, error) {
	if kg == nil {
		return nil, fmt.Errorf("GenerateKeyPair: arguments must not be nil")
	}

	p, err := kg.generatePrime()
	if err != nil {
		return nil, fmt.Errorf("GenerateKeyPair: %w", err)
	}

	q, err := kg.generatePrimeDistinctFrom(p)
	if err != nil {
		return nil, fmt.Errorf("GenerateKeyPair: %w", err)
	}

	value, err := kg.checkFermatAttackResistance(p, q)
	if err != nil {
		return nil, fmt.Errorf("GenerateKeyPair: %w", err)
	}

	if !value {
		return nil, fmt.Errorf("keys are vulnerable to a Farm attack, regeneration is needed")
	}

	N := new(big.Int).Mul(p, q)

	phi, err := kg.calculatePhi(p, q)
	if err != nil {
		return nil, fmt.Errorf("GenerateKeyPair: %w", err)
	}

	e := big.NewInt(65537)
	d, err := kg.calculatePrivateExponent(e, phi)
	if err != nil {
		return nil, fmt.Errorf("GenerateKeyPair: %w", err)
	}

	value, err = kg.checkWienerAttackResistance(d, N)
	if err != nil {
		return nil, fmt.Errorf("GenerateKeyPair: %w", err)
	}

	if !value {
		return nil, fmt.Errorf("keys are vulnerable to Wiener attack, regeneration is needed")
	}

	return &RSAKeyPair{
		PublicKey: &RSAPublicKey{
			N: N,
			E: e,
		},
		PrivateKey: &RSAPrivateKey{
			N: N,
			D: d,
		},
		P: p,
		Q: q,
	}, nil
}

func (kg *KeyGenerator) generatePrime() (*big.Int, error) {
	if kg == nil {
		return nil, fmt.Errorf("generatePrime: arguments must not be nil")
	}

	maxAttempts := 1000

	for attempt := 0; attempt < maxAttempts; attempt++ {
		candidate, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), uint(kg.bitLength)))
		if err != nil {
			return nil, fmt.Errorf("generatePrime: failed to generate random number: %w", err)
		}

		candidate.SetBit(candidate, kg.bitLength-1, 1)
		candidate.SetBit(candidate, 0, 1)

		isPrime, err := kg.primalityTester.IsProbablyPrime(candidate, kg.minProbability)
		if err != nil {
			continue
		}

		if isPrime {
			return candidate, nil
		}
	}

	return nil, fmt.Errorf("failed to generate a prime number after %d attempts", maxAttempts)
}

func (kg *KeyGenerator) generatePrimeDistinctFrom(other *big.Int) (*big.Int, error) {
	if kg == nil || other == nil {
		return nil, fmt.Errorf("generatePrimeDistinctFrom: arguments must not be nil")
	}

	maxAttempts := 1000

	for i := 0; i < maxAttempts; i++ {
		candidate, err := kg.generatePrime()
		if err != nil {
			continue
		}

		if candidate.Cmp(other) != 0 {
			return candidate, nil
		}
	}

	return nil, fmt.Errorf("failed to generate a prime number")
}

func (kg *KeyGenerator) checkFermatAttackResistance(p, q *big.Int) (bool, error) {
	if kg == nil || p == nil || q == nil {
		return false, fmt.Errorf("checkFermatAttackResistance: arguments must not be nil")
	}

	diff := new(big.Int).Sub(p, q)
	diff.Abs(diff)
	minDiffBits := kg.bitLength/2 - 100
	if minDiffBits < 1 {
		minDiffBits = 1
	}
	minDiff := new(big.Int).Lsh(big.NewInt(1), uint(minDiffBits))

	return diff.Cmp(minDiff) > 0, nil
}

func (kg *KeyGenerator) checkWienerAttackResistance(d, N *big.Int) (bool, error) {
	if kg == nil || d == nil || N == nil {
		return false, fmt.Errorf("checkWienerAttackResistance: arguments must not be nil")
	}

	sqrtN := new(big.Int).Sqrt(N)
	sqrtSqrtN := new(big.Int).Sqrt(sqrtN)

	return d.Cmp(sqrtSqrtN) > 0, nil
}

func (kg *KeyGenerator) calculatePhi(p, q *big.Int) (*big.Int, error) {
	if kg == nil || p == nil || q == nil {
		return nil, fmt.Errorf("calculatePhi: arguments must not be nil")
	}

	pMinus1 := new(big.Int).Sub(p, big.NewInt(1))
	qMinus1 := new(big.Int).Sub(q, big.NewInt(1))

	return new(big.Int).Mul(pMinus1, qMinus1), nil
}

func (kg *KeyGenerator) calculatePrivateExponent(e, phi *big.Int) (*big.Int, error) {
	if kg == nil || e == nil || phi == nil {
		return nil, fmt.Errorf("calculatePrivateExponent: arguments must not be nil")
	}

	gcd, d, _, err := statelessService.ExtendedGCD(e, phi)
	if err != nil {
		return nil, fmt.Errorf("calculatePrivateExponent: %w", err)
	}

	if gcd.Cmp(big.NewInt(1)) != 0 {
		return nil, fmt.Errorf("gcd(e, phi(N) != 1")
	}

	if d.Sign() < 0 {
		d.Add(d, phi)
	}

	check := new(big.Int).Mul(e, d)
	check.Mod(check, phi)
	if check.Cmp(big.NewInt(1)) != 0 {
		return nil, fmt.Errorf("calculated d is not inverse of e mod phi(N)")
	}

	return d, nil
}

type RSAService struct {
	keyGenerator *KeyGenerator
	currentKeys  *RSAKeyPair
}

func NewRSAService(testType PrimalityTestType, minProbability float64, bitLength int) (*RSAService, error) {
	keyGen, err := NewKeyGenerator(testType, minProbability, bitLength)
	if err != nil {
		return nil, fmt.Errorf("NewRSAService: %w", err)
	}

	return &RSAService{
		keyGenerator: keyGen,
	}, nil
}

func (rs *RSAService) GenerateKeys() error {
	if rs == nil {
		return fmt.Errorf("GenerateKeys: arguments must not be nil")
	}

	keys, err := rs.keyGenerator.GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("GenerateKeys: %w", err)
	}

	rs.currentKeys = keys
	return nil
}

func (rs *RSAService) GetPublicKey() (*RSAPublicKey, error) {
	if rs == nil || rs.currentKeys == nil {
		return nil, fmt.Errorf("GetPublicKey: arguments must not be nil")
	}
	return rs.currentKeys.PublicKey, nil
}

func (rs *RSAService) Encrypt(message *big.Int) (*big.Int, error) {
	if rs == nil || rs.currentKeys == nil || message == nil {
		return nil, fmt.Errorf("Encrypt: arguments must not be nil")
	}

	pub := rs.currentKeys.PublicKey

	if message.Cmp(pub.N) >= 0 {
		return nil, fmt.Errorf("the message is too big (>= N)")
	}

	ciphertext, err := statelessService.ModPow(message, pub.E, pub.N)
	if err != nil {
		return nil, fmt.Errorf("Encrypt: %w", err)
	}

	return ciphertext, nil
}

func (rs *RSAService) Decrypt(ciphertext *big.Int) (*big.Int, error) {
	if rs == nil || rs.currentKeys == nil || ciphertext == nil {
		return nil, fmt.Errorf("Decrypt: arguments must not be nil")
	}

	priv := rs.currentKeys.PrivateKey

	message, err := statelessService.ModPow(ciphertext, priv.D, priv.N)
	if err != nil {
		return nil, fmt.Errorf("Decrypt: %w", err)
	}

	return message, nil
}

func (rs *RSAService) GetKeyInfo() string {
	if rs == nil || rs.currentKeys == nil {
		return "The keys are not generated"
	}

	return fmt.Sprintf("\nRSA Key Information:\n  N (modulus): %d bits\n  E (public exponent): %s\n  D (private exponent): %d bits\n  P: %d bits\n  Q: %d bits\n  |P - Q|: %d bits\n",
		rs.currentKeys.PublicKey.N.BitLen(),
		rs.currentKeys.PublicKey.E.String(),
		rs.currentKeys.PrivateKey.D.BitLen(),
		rs.currentKeys.P.BitLen(),
		rs.currentKeys.Q.BitLen(),
		new(big.Int).Sub(rs.currentKeys.P, rs.currentKeys.Q).BitLen(),
	)
}
