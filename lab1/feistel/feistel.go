package feistel

//package main

import (
	"errors"
	"fmt"
	"lab1/interfaces"
)

type FeistelFunction interface {
	Apply(rightHalf []byte, roundKey []byte) ([]byte, error)
	HalfBlockSize() int
}

type FeistelKeySchedule interface {
	interfaces.KeyExpander
	NumRounds() int
}

type FeistelNetwork struct {
	fFunction     FeistelFunction
	keySchedule   FeistelKeySchedule
	roundKeys     [][]byte
	numRounds     int
	halfBlockSize int
}

func NewFeistelNetwork(fFunc FeistelFunction, keySched FeistelKeySchedule) (*FeistelNetwork, error) {
	if fFunc == nil || keySched == nil {
		return nil, errors.New("arguments cannot be nil")
	}

	return &FeistelNetwork{
		fFunction:     fFunc,
		keySchedule:   keySched,
		numRounds:     keySched.NumRounds(),
		halfBlockSize: fFunc.HalfBlockSize(),
	}, nil
}

func (fn *FeistelNetwork) Transform(inputBlock []byte, roundKey []byte) ([]byte, error) {
	expectedSize := fn.halfBlockSize * 2
	if len(inputBlock) != expectedSize {
		return nil, fmt.Errorf("input block must be %d bytes", expectedSize)
	}

	left := make([]byte, fn.halfBlockSize)
	right := make([]byte, fn.halfBlockSize)
	copy(left, inputBlock[:fn.halfBlockSize])
	copy(right, inputBlock[fn.halfBlockSize:])

	fResult, err := fn.fFunction.Apply(right, roundKey)
	if err != nil {
		return nil, err
	}

	newLeft := make([]byte, fn.halfBlockSize)
	newRight := make([]byte, fn.halfBlockSize)

	copy(newLeft, right)
	copy(newRight, left)
	interfaces.XorBytes(newRight, fResult)

	result := make([]byte, expectedSize)
	copy(result[:fn.halfBlockSize], newLeft)
	copy(result[fn.halfBlockSize:], newRight)
	return result, nil
}

func (fn *FeistelNetwork) reverseTransform(inputBlock []byte, roundKey []byte) ([]byte, error) {
	expectedSize := fn.halfBlockSize * 2
	if len(inputBlock) != expectedSize {
		return nil, fmt.Errorf("input block must be %d bytes", expectedSize)
	}

	left := make([]byte, fn.halfBlockSize)
	right := make([]byte, fn.halfBlockSize)
	copy(left, inputBlock[:fn.halfBlockSize])
	copy(right, inputBlock[fn.halfBlockSize:])

	fResult, err := fn.fFunction.Apply(left, roundKey)
	if err != nil {
		return nil, err
	}

	newLeft := make([]byte, fn.halfBlockSize)
	newRight := make([]byte, fn.halfBlockSize)

	copy(newRight, left)
	copy(newLeft, right)
	interfaces.XorBytes(newLeft, fResult)

	result := make([]byte, expectedSize)
	copy(result[:fn.halfBlockSize], newLeft)
	copy(result[fn.halfBlockSize:], newRight)
	return result, nil
}

func (fn *FeistelNetwork) SetKey(key []byte) error {
	roundKeys, err := fn.keySchedule.ExpandKey(key)
	if err != nil {
		return err
	}
	fn.roundKeys = roundKeys
	return nil
}

func (fn *FeistelNetwork) BlockSize() int {
	return fn.halfBlockSize * 2
}

func (fn *FeistelNetwork) Encrypt(block []byte) ([]byte, error) {
	if len(fn.roundKeys) == 0 {
		return nil, errors.New("round keys not set")
	}

	result := make([]byte, len(block))
	copy(result, block)

	for i := 0; i < fn.numRounds; i++ {
		var err error
		result, err = fn.Transform(result, fn.roundKeys[i])
		if err != nil {
			return nil, err
		}
	}
	return result, nil
}

func (fn *FeistelNetwork) Decrypt(block []byte) ([]byte, error) {
	if len(fn.roundKeys) == 0 {
		return nil, errors.New("round keys not set")
	}

	result := make([]byte, len(block))
	copy(result, block)

	for i := fn.numRounds - 1; i >= 0; i-- {
		var err error
		result, err = fn.reverseTransform(result, fn.roundKeys[i])
		if err != nil {
			return nil, err
		}
	}
	return result, nil
}

type SimpleFeistelFunction struct {
	halfBlockSize int
}

func NewSimpleFeistelFunction(halfBlockSize int) *SimpleFeistelFunction {
	return &SimpleFeistelFunction{halfBlockSize}
}

func (sff *SimpleFeistelFunction) Apply(rightHalf []byte, roundKey []byte) ([]byte, error) {
	result := make([]byte, sff.halfBlockSize)
	for i := 0; i < sff.halfBlockSize; i++ {
		keyByte := roundKey[i%len(roundKey)]
		result[i] = rightHalf[i] ^ keyByte
	}
	return result, nil
}

func (sff *SimpleFeistelFunction) HalfBlockSize() int {
	return sff.halfBlockSize
}

type SimpleFeistelKeySchedule struct {
	numRounds int
}

func NewSimpleFeistelKeySchedule(numRounds int) *SimpleFeistelKeySchedule {
	return &SimpleFeistelKeySchedule{numRounds}
}

func (sfks *SimpleFeistelKeySchedule) ExpandKey(key []byte) ([][]byte, error) {
	roundKeys := make([][]byte, sfks.numRounds)
	for i := 0; i < sfks.numRounds; i++ {
		roundKey := make([]byte, len(key))
		for j := 0; j < len(key); j++ {
			roundKey[j] = key[(i+j)%len(key)]
		}
		roundKeys[i] = roundKey
	}
	return roundKeys, nil
}

func (sfks *SimpleFeistelKeySchedule) NumRounds() int {
	return sfks.numRounds
}
