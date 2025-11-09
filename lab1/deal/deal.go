package deal

//package main

import (
	"fmt"
	"lab1/des"
	"lab1/feistel"
)

type DEALAdapter struct {
	desInstance *des.DES
	tempKey     []byte
}

func NewDEALAdapter(desInstance *des.DES) *DEALAdapter {
	return &DEALAdapter{
		desInstance: desInstance,
		tempKey:     []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF},
	}
}

func (da *DEALAdapter) Apply(rightHalf []byte, roundKey []byte) ([]byte, error) {
	if len(rightHalf) != 8 {
		return nil, fmt.Errorf("DEAL adapter: right half must be 8 bytes (got %d)", len(rightHalf))
	}

	desInstance, err := des.NewDES()
	if err != nil {
		return nil, fmt.Errorf("failed to create DES: %w", err)
	}

	if len(roundKey) >= 8 {
		desKey := make([]byte, 8)
		copy(desKey, roundKey[:8])

		err := desInstance.SetKey(desKey)
		if err != nil {
			return nil, fmt.Errorf("failed to set DES key: %w", err)
		}
	}

	result, err := desInstance.Encrypt(rightHalf)
	if err != nil {
		return nil, fmt.Errorf("DES encryption failed: %w", err)
	}

	return result, nil
}

func (da *DEALAdapter) HalfBlockSize() int {
	return 8
}

type DEALKeySchedule struct {
	numRounds int
	keySize   int
}

func NewDEALKeySchedule(numRounds int) *DEALKeySchedule {
	return &DEALKeySchedule{
		numRounds: numRounds,
		keySize:   16,
	}
}

func (dks *DEALKeySchedule) ExpandKey(key []byte) ([][]byte, error) {
	if len(key) != dks.keySize {
		return nil, fmt.Errorf("DEAL key must be %d bytes (got %d)", dks.keySize, len(key))
	}

	roundKeys := make([][]byte, dks.numRounds)

	for i := 0; i < dks.numRounds; i++ {
		roundKey := make([]byte, 8)
		for j := 0; j < 8; j++ {
			idx := (i*2 + j) % len(key)
			roundKey[j] = key[idx] ^ byte(i+1) ^ byte(j<<1)
		}
		roundKeys[i] = roundKey
	}

	return roundKeys, nil
}

func (dks *DEALKeySchedule) NumRounds() int {
	return dks.numRounds
}

type DEAL struct {
	network    *feistel.FeistelNetwork
	desAdapter *DEALAdapter
	numRounds  int
}

func NewDEAL(numRounds int) (*DEAL, error) {
	desInstance, err := des.NewDES()
	if err != nil {
		return nil, fmt.Errorf("failed to create DES instance: %w", err)
	}

	adapter := NewDEALAdapter(desInstance)
	keySchedule := NewDEALKeySchedule(numRounds)

	dealNetwork, err := feistel.NewFeistelNetwork(adapter, keySchedule)
	if err != nil {
		return nil, fmt.Errorf("failed to create DEAL network: %w", err)
	}

	return &DEAL{
		network:    dealNetwork,
		desAdapter: adapter,
		numRounds:  numRounds,
	}, nil
}

func (d *DEAL) SetKey(key []byte) error {
	return d.network.SetKey(key)
}

func (d *DEAL) Encrypt(block []byte) ([]byte, error) {
	if len(block) != 16 {
		return nil, fmt.Errorf("DEAL block must be 16 bytes (got %d)", len(block))
	}
	return d.network.Encrypt(block)
}

func (d *DEAL) Decrypt(block []byte) ([]byte, error) {
	if len(block) != 16 {
		return nil, fmt.Errorf("DEAL block must be 16 bytes (got %d)", len(block))
	}
	return d.network.Decrypt(block)
}

func (d *DEAL) BlockSize() int {
	return 16
}

func (d *DEAL) NumRounds() int {
	return d.numRounds
}

/*func main() {
	deal, err := NewDEAL(6)
	if err != nil {
		panic(err)
	}

	key := []byte{
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
		0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
	}
	fmt.Printf("Key:\t\t% x\n", key)

	err = deal.SetKey(key)
	if err != nil {
		panic(err)
	}

	plaintext := []byte{
		0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
		0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
	}
	fmt.Printf("Plaintext:\t% x\n", plaintext)

	encrypted, err := deal.Encrypt(plaintext)
	if err != nil {
		fmt.Printf("Encryption error: %v\n", err)
		return
	}
	fmt.Printf("Encrypted:\t% x\n", encrypted)

	decrypted, err := deal.Decrypt(encrypted)
	if err != nil {
		fmt.Printf("Decryption error: %v\n", err)
		return
	}
	fmt.Printf("Decrypted:\t% x\n", decrypted)
}*/
