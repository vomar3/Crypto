package tripledes

import (
	"errors"
	"fmt"
	"lab1/des"
)

type TripleDESMode int

const (
	EDE TripleDESMode = iota
	EEE
)

type TripleDES struct {
	des1 *des.DES
	des2 *des.DES
	des3 *des.DES
	mode TripleDESMode
	key1 []byte
	key2 []byte
	key3 []byte
}

func NewTripleDES(mode TripleDESMode) (*TripleDES, error) {
	des1, err := des.NewDES()
	if err != nil {
		return nil, fmt.Errorf("failed to create DES1: %w", err)
	}

	des2, err := des.NewDES()
	if err != nil {
		return nil, fmt.Errorf("failed to create DES2: %w", err)
	}

	des3, err := des.NewDES()
	if err != nil {
		return nil, fmt.Errorf("failed to create DES3: %w", err)
	}

	return &TripleDES{
		des1: des1,
		des2: des2,
		des3: des3,
		mode: mode,
	}, nil
}

func (t *TripleDES) SetKey(key []byte) error {
	switch len(key) {
	case 8:
		t.key1 = make([]byte, 8)
		t.key2 = make([]byte, 8)
		t.key3 = make([]byte, 8)
		copy(t.key1, key)
		copy(t.key2, key)
		copy(t.key3, key)

	case 16:
		t.key1 = make([]byte, 8)
		t.key2 = make([]byte, 8)
		t.key3 = make([]byte, 8)
		copy(t.key1, key[:8])
		copy(t.key2, key[8:16])
		copy(t.key3, key[:8])

	case 24:
		t.key1 = make([]byte, 8)
		t.key2 = make([]byte, 8)
		t.key3 = make([]byte, 8)
		copy(t.key1, key[:8])
		copy(t.key2, key[8:16])
		copy(t.key3, key[16:24])

	default:
		return fmt.Errorf("invalid key length: %d (must be 8, 16, or 24 bytes)", len(key))
	}

	if err := t.des1.SetKey(t.key1); err != nil {
		return fmt.Errorf("failed to set key1: %w", err)
	}

	if err := t.des2.SetKey(t.key2); err != nil {
		return fmt.Errorf("failed to set key2: %w", err)
	}

	if err := t.des3.SetKey(t.key3); err != nil {
		return fmt.Errorf("failed to set key3: %w", err)
	}

	return nil
}

func (t *TripleDES) Encrypt(block []byte) ([]byte, error) {
	if len(block) != 8 {
		return nil, errors.New("block size must be 8 bytes")
	}

	var result []byte
	var err error

	switch t.mode {
	case EDE:
		result, err = t.des1.Encrypt(block)
		if err != nil {
			return nil, fmt.Errorf("DES1 encryption failed: %w", err)
		}

		result, err = t.des2.Decrypt(result)
		if err != nil {
			return nil, fmt.Errorf("DES2 decryption failed: %w", err)
		}

		result, err = t.des3.Encrypt(result)
		if err != nil {
			return nil, fmt.Errorf("DES3 encryption failed: %w", err)
		}

	case EEE:
		result, err = t.des1.Encrypt(block)
		if err != nil {
			return nil, fmt.Errorf("DES1 encryption failed: %w", err)
		}

		result, err = t.des2.Encrypt(result)
		if err != nil {
			return nil, fmt.Errorf("DES2 encryption failed: %w", err)
		}

		result, err = t.des3.Encrypt(result)
		if err != nil {
			return nil, fmt.Errorf("DES3 encryption failed: %w", err)
		}

	default:
		return nil, fmt.Errorf("unsupported TripleDES mode: %d", t.mode)
	}

	return result, nil
}

func (t *TripleDES) Decrypt(block []byte) ([]byte, error) {
	if len(block) != 8 {
		return nil, errors.New("block size must be 8 bytes")
	}

	var result []byte
	var err error

	switch t.mode {
	case EDE:
		result, err = t.des3.Decrypt(block)
		if err != nil {
			return nil, fmt.Errorf("DES3 decryption failed: %w", err)
		}

		result, err = t.des2.Encrypt(result)
		if err != nil {
			return nil, fmt.Errorf("DES2 encryption failed: %w", err)
		}

		result, err = t.des1.Decrypt(result)
		if err != nil {
			return nil, fmt.Errorf("DES1 decryption failed: %w", err)
		}

	case EEE:
		result, err = t.des3.Decrypt(block)
		if err != nil {
			return nil, fmt.Errorf("DES3 decryption failed: %w", err)
		}

		result, err = t.des2.Decrypt(result)
		if err != nil {
			return nil, fmt.Errorf("DES2 decryption failed: %w", err)
		}

		result, err = t.des1.Decrypt(result)
		if err != nil {
			return nil, fmt.Errorf("DES1 decryption failed: %w", err)
		}

	default:
		return nil, fmt.Errorf("unsupported TripleDES mode: %d", t.mode)
	}

	return result, nil
}

func (t *TripleDES) BlockSize() int {
	return 8
}
