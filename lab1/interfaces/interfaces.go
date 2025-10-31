package interfaces

// package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
)

type KeyExpander interface {
	ExpandKey(key []byte) ([][]byte, error)
}

type RoundTransformer interface {
	Transform(inputBlock []byte, roundKey []byte) ([]byte, error)
}

type BlockCipher interface {
	SetKey(key []byte) error
	Encrypt(block []byte) ([]byte, error)
	Decrypt(block []byte) ([]byte, error)
	BlockSize() int
}

type CipherMode int

const (
	ECB CipherMode = iota
	CBC
	PCBC
	CFB
	OFB
	CTR
	RandomDelta
)

func (cm CipherMode) String() string {
	switch cm {
	case ECB:
		return "ECB"
	case CBC:
		return "CBC"
	case PCBC:
		return "PCBC"
	case CFB:
		return "CFB"
	case OFB:
		return "OFB"
	case CTR:
		return "CTR"
	case RandomDelta:
		return "RandomDelta"
	default:
		return "Unknown"
	}
}

type PaddingMode int

const (
	Zeros PaddingMode = iota
	ANSIX923
	PKCS7
	ISO10126
)

func (pm PaddingMode) String() string {
	switch pm {
	case Zeros:
		return "Zeros"
	case ANSIX923:
		return "ANSIX923"
	case PKCS7:
		return "PKCS7"
	case ISO10126:
		return "ISO10126"
	default:
		return "Unknown"
	}
}

type CipherContextConfig struct {
	Key            []byte
	Mode           CipherMode
	Padding        PaddingMode
	IV             []byte
	AdditionalArgs []interface{}
}

type CipherContext struct {
	cipher         BlockCipher
	mode           CipherMode
	padding        PaddingMode
	iv             []byte
	additionalArgs []interface{}
	blockSize      int
}

func NewCipherContext(cipher BlockCipher, config CipherContextConfig) (*CipherContext, error) {
	if cipher == nil {
		return nil, errors.New("cipher cannot be nil")
	}

	if err := cipher.SetKey(config.Key); err != nil {
		return nil, fmt.Errorf("failed to set key: %w", err)
	}

	blockSize := cipher.BlockSize()

	iv := config.IV
	if iv == nil && requiresIV(config.Mode) {
		iv = make([]byte, blockSize)
		if _, err := io.ReadFull(rand.Reader, iv); err != nil {
			return nil, fmt.Errorf("failed to generate IV: %w", err)
		}
	}

	if iv != nil && len(iv) != blockSize {
		return nil, fmt.Errorf("IV length must be equal to block size (%d bytes)", blockSize)
	}

	return &CipherContext{
		cipher:         cipher,
		mode:           config.Mode,
		padding:        config.Padding,
		iv:             iv,
		additionalArgs: config.AdditionalArgs,
		blockSize:      blockSize,
	}, nil
}

func requiresIV(mode CipherMode) bool {
	switch mode {
	case CBC, PCBC, CFB, OFB, CTR:
		return true
	default:
		return false
	}
}

type encryptResult struct {
	data []byte
	err  error
}

func (cc *CipherContext) EncryptBytes(ctx context.Context, plaintext []byte) ([]byte, error) {
	resultCh := make(chan encryptResult, 1)

	go func() {
		defer close(resultCh)

		select {
		case <-ctx.Done():
			resultCh <- encryptResult{err: ctx.Err()}
			return
		default:
		}

		paddedData, err := cc.applyPadding(plaintext)
		if err != nil {
			resultCh <- encryptResult{err: err}
			return
		}

		var ciphertext []byte
		switch cc.mode {
		case ECB:
			ciphertext, err = cc.encryptECB(ctx, paddedData)
		case CBC:
			ciphertext, err = cc.encryptCBC(ctx, paddedData)
		case PCBC:
			ciphertext, err = cc.encryptPCBC(ctx, paddedData)
		case CFB:
			ciphertext, err = cc.encryptCFB(ctx, paddedData)
		case OFB:
			ciphertext, err = cc.encryptOFB(ctx, paddedData)
		case CTR:
			ciphertext, err = cc.encryptCTR(ctx, paddedData)
		case RandomDelta:
			ciphertext, err = cc.encryptRandomDelta(ctx, paddedData)
		default:
			err = fmt.Errorf("unsupported cipher mode: %v", cc.mode)
		}

		resultCh <- encryptResult{data: ciphertext, err: err}
	}()

	select {
	case result := <-resultCh:
		return result.data, result.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (cc *CipherContext) EncryptBytesTo(ctx context.Context, plaintext []byte, result *[]byte) error {
	ciphertext, err := cc.EncryptBytes(ctx, plaintext)
	if err != nil {
		return err
	}
	*result = ciphertext
	return nil
}

func (cc *CipherContext) DecryptBytes(ctx context.Context, ciphertext []byte) ([]byte, error) {
	resultCh := make(chan encryptResult, 1)

	go func() {
		defer close(resultCh)

		select {
		case <-ctx.Done():
			resultCh <- encryptResult{err: ctx.Err()}
			return
		default:
		}

		var plaintext []byte
		var err error
		switch cc.mode {
		case ECB:
			plaintext, err = cc.decryptECB(ctx, ciphertext)
		case CBC:
			plaintext, err = cc.decryptCBC(ctx, ciphertext)
		case PCBC:
			plaintext, err = cc.decryptPCBC(ctx, ciphertext)
		case CFB:
			plaintext, err = cc.decryptCFB(ctx, ciphertext)
		case OFB:
			plaintext, err = cc.decryptOFB(ctx, ciphertext)
		case CTR:
			plaintext, err = cc.decryptCTR(ctx, ciphertext)
		case RandomDelta:
			plaintext, err = cc.decryptRandomDelta(ctx, ciphertext)
		default:
			err = fmt.Errorf("unsupported cipher mode: %v", cc.mode)
		}

		if err != nil {
			resultCh <- encryptResult{err: err}
			return
		}

		unpaddedData, err := cc.removePadding(plaintext)
		resultCh <- encryptResult{data: unpaddedData, err: err}
	}()

	select {
	case result := <-resultCh:
		return result.data, result.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (cc *CipherContext) DecryptBytesTo(ctx context.Context, ciphertext []byte, result *[]byte) error {
	plaintext, err := cc.DecryptBytes(ctx, ciphertext)
	if err != nil {
		return err
	}
	*result = plaintext
	return nil
}

func (cc *CipherContext) EncryptFile(ctx context.Context, inputPath, outputPath string) error {
	resultCh := make(chan error, 1)

	go func() {
		defer close(resultCh)

		plaintext, err := os.ReadFile(inputPath)
		if err != nil {
			resultCh <- fmt.Errorf("failed to read input file: %w", err)
			return
		}

		ciphertext, err := cc.EncryptBytes(ctx, plaintext)
		if err != nil {
			resultCh <- fmt.Errorf("encryption failed: %w", err)
			return
		}

		if err := os.WriteFile(outputPath, ciphertext, 0644); err != nil {
			resultCh <- fmt.Errorf("failed to write output file: %w", err)
			return
		}

		resultCh <- nil
	}()

	select {
	case err := <-resultCh:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (cc *CipherContext) DecryptFile(ctx context.Context, inputPath, outputPath string) error {
	resultCh := make(chan error, 1)

	go func() {
		defer close(resultCh)

		ciphertext, err := os.ReadFile(inputPath)
		if err != nil {
			resultCh <- fmt.Errorf("failed to read input file: %w", err)
			return
		}

		plaintext, err := cc.DecryptBytes(ctx, ciphertext)
		if err != nil {
			resultCh <- fmt.Errorf("decryption failed: %w", err)
			return
		}

		if err := os.WriteFile(outputPath, plaintext, 0644); err != nil {
			resultCh <- fmt.Errorf("failed to write output file: %w", err)
			return
		}

		resultCh <- nil
	}()

	select {
	case err := <-resultCh:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (cc *CipherContext) encryptECB(ctx context.Context, data []byte) ([]byte, error) {
	numBlocks := len(data) / cc.blockSize
	ciphertext := make([]byte, len(data))

	var wg sync.WaitGroup
	errCh := make(chan error, numBlocks)

	maxWorkers := min(numBlocks, 8)
	blocksCh := make(chan int, numBlocks)

	for i := 0; i < numBlocks; i++ {
		blocksCh <- i
	}
	close(blocksCh)

	for w := 0; w < maxWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for blockIdx := range blocksCh {
				select {
				case <-ctx.Done():
					errCh <- ctx.Err()
					return
				default:
				}

				start := blockIdx * cc.blockSize
				end := start + cc.blockSize
				block := data[start:end]

				encrypted, err := cc.cipher.Encrypt(block)
				if err != nil {
					errCh <- err
					return
				}
				copy(ciphertext[start:end], encrypted)
			}
		}()
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		if err != nil {
			return nil, err
		}
	}

	return ciphertext, nil
}

func (cc *CipherContext) decryptECB(ctx context.Context, data []byte) ([]byte, error) {
	if len(data)%cc.blockSize != 0 {
		return nil, errors.New("ciphertext length must be multiple of block size")
	}

	numBlocks := len(data) / cc.blockSize
	plaintext := make([]byte, len(data))

	var wg sync.WaitGroup
	errCh := make(chan error, numBlocks)

	maxWorkers := min(numBlocks, 8)
	blocksCh := make(chan int, numBlocks)

	for i := 0; i < numBlocks; i++ {
		blocksCh <- i
	}
	close(blocksCh)

	for w := 0; w < maxWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for blockIdx := range blocksCh {
				select {
				case <-ctx.Done():
					errCh <- ctx.Err()
					return
				default:
				}

				start := blockIdx * cc.blockSize
				end := start + cc.blockSize
				block := data[start:end]

				decrypted, err := cc.cipher.Decrypt(block)
				if err != nil {
					errCh <- err
					return
				}
				copy(plaintext[start:end], decrypted)
			}
		}()
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		if err != nil {
			return nil, err
		}
	}

	return plaintext, nil
}

func (cc *CipherContext) encryptCBC(ctx context.Context, data []byte) ([]byte, error) {
	if len(data)%cc.blockSize != 0 {
		return nil, errors.New("data length must be multiple of block size")
	}

	numBlocks := len(data) / cc.blockSize
	ciphertext := make([]byte, len(data))
	prevBlock := make([]byte, cc.blockSize)
	copy(prevBlock, cc.iv)

	for i := 0; i < numBlocks; i++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		start := i * cc.blockSize
		end := start + cc.blockSize
		block := make([]byte, cc.blockSize)
		copy(block, data[start:end])

		XorBytes(block, prevBlock)

		encrypted, err := cc.cipher.Encrypt(block)
		if err != nil {
			return nil, err
		}

		copy(ciphertext[start:end], encrypted)
		copy(prevBlock, encrypted)
	}

	return ciphertext, nil
}

func (cc *CipherContext) decryptCBC(ctx context.Context, data []byte) ([]byte, error) {
	if len(data)%cc.blockSize != 0 {
		return nil, errors.New("ciphertext length must be multiple of block size")
	}

	numBlocks := len(data) / cc.blockSize
	plaintext := make([]byte, len(data))
	var wg sync.WaitGroup
	errCh := make(chan error, numBlocks)

	maxWorkers := min(numBlocks, 8)
	blocksCh := make(chan int, numBlocks)

	for i := 0; i < numBlocks; i++ {
		blocksCh <- i
	}
	close(blocksCh)

	for w := 0; w < maxWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for blockIdx := range blocksCh {
				select {
				case <-ctx.Done():
					errCh <- ctx.Err()
					return
				default:
				}

				start := blockIdx * cc.blockSize
				end := start + cc.blockSize
				block := data[start:end]

				decrypted, err := cc.cipher.Decrypt(block)
				if err != nil {
					errCh <- err
					return
				}

				var prevBlock []byte
				if blockIdx == 0 {
					prevBlock = cc.iv
				} else {
					prevStart := (blockIdx - 1) * cc.blockSize
					prevEnd := prevStart + cc.blockSize
					prevBlock = data[prevStart:prevEnd]
				}

				XorBytes(decrypted, prevBlock)
				copy(plaintext[start:end], decrypted)
			}
		}()
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		if err != nil {
			return nil, err
		}
	}

	return plaintext, nil
}

func (cc *CipherContext) encryptPCBC(ctx context.Context, data []byte) ([]byte, error) {
	if len(data)%cc.blockSize != 0 {
		return nil, errors.New("data length must be multiple of block size")
	}

	numBlocks := len(data) / cc.blockSize
	ciphertext := make([]byte, len(data))
	prevXOR := make([]byte, cc.blockSize)
	copy(prevXOR, cc.iv)

	for i := 0; i < numBlocks; i++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		start := i * cc.blockSize
		end := start + cc.blockSize
		block := make([]byte, cc.blockSize)
		copy(block, data[start:end])

		XorBytes(block, prevXOR)

		encrypted, err := cc.cipher.Encrypt(block)
		if err != nil {
			return nil, err
		}

		copy(ciphertext[start:end], encrypted)
		copy(prevXOR, data[start:end])
		XorBytes(prevXOR, encrypted)
	}

	return ciphertext, nil
}

func (cc *CipherContext) decryptPCBC(ctx context.Context, data []byte) ([]byte, error) {
	if len(data)%cc.blockSize != 0 {
		return nil, errors.New("ciphertext length must be multiple of block size")
	}

	numBlocks := len(data) / cc.blockSize
	plaintext := make([]byte, len(data))
	prevXOR := make([]byte, cc.blockSize)
	copy(prevXOR, cc.iv)

	for i := 0; i < numBlocks; i++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		start := i * cc.blockSize
		end := start + cc.blockSize
		block := data[start:end]

		decrypted, err := cc.cipher.Decrypt(block)
		if err != nil {
			return nil, err
		}

		XorBytes(decrypted, prevXOR)
		copy(plaintext[start:end], decrypted)
		copy(prevXOR, decrypted)
		XorBytes(prevXOR, block)
	}

	return plaintext, nil
}

func (cc *CipherContext) encryptCFB(ctx context.Context, data []byte) ([]byte, error) {
	ciphertext := make([]byte, len(data))
	iv := make([]byte, cc.blockSize)
	copy(iv, cc.iv)

	for i := 0; i < len(data); i += cc.blockSize {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		encrypted, err := cc.cipher.Encrypt(iv)
		if err != nil {
			return nil, err
		}

		blockSize := min(cc.blockSize, len(data)-i)

		for j := 0; j < blockSize; j++ {
			ciphertext[i+j] = data[i+j] ^ encrypted[j]
		}

		copy(iv, ciphertext[i:i+blockSize])
		if blockSize < cc.blockSize {
			copy(iv[blockSize:], encrypted[blockSize:])
		}
	}

	return ciphertext, nil
}

func (cc *CipherContext) decryptCFB(ctx context.Context, data []byte) ([]byte, error) {
	plaintext := make([]byte, len(data))
	iv := make([]byte, cc.blockSize)
	copy(iv, cc.iv)

	for i := 0; i < len(data); i += cc.blockSize {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		encrypted, err := cc.cipher.Encrypt(iv)
		if err != nil {
			return nil, err
		}

		blockSize := min(cc.blockSize, len(data)-i)

		for j := 0; j < blockSize; j++ {
			plaintext[i+j] = data[i+j] ^ encrypted[j]
		}

		copy(iv, data[i:i+blockSize])
		if blockSize < cc.blockSize {
			copy(iv[blockSize:], encrypted[blockSize:])
		}
	}

	return plaintext, nil
}

func (cc *CipherContext) encryptOFB(ctx context.Context, data []byte) ([]byte, error) {
	ciphertext := make([]byte, len(data))
	iv := make([]byte, cc.blockSize)
	copy(iv, cc.iv)

	for i := 0; i < len(data); i += cc.blockSize {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		encrypted, err := cc.cipher.Encrypt(iv)
		if err != nil {
			return nil, err
		}

		blockSize := min(cc.blockSize, len(data)-i)

		for j := 0; j < blockSize; j++ {
			ciphertext[i+j] = data[i+j] ^ encrypted[j]
		}

		copy(iv, encrypted)
	}

	return ciphertext, nil
}

func (cc *CipherContext) decryptOFB(ctx context.Context, data []byte) ([]byte, error) {
	return cc.encryptOFB(ctx, data)
}

func (cc *CipherContext) encryptCTR(ctx context.Context, data []byte) ([]byte, error) {
	ciphertext := make([]byte, len(data))

	counter := make([]byte, cc.blockSize)
	copy(counter, cc.iv)

	numBlocks := (len(data) + cc.blockSize - 1) / cc.blockSize

	var wg sync.WaitGroup
	errCh := make(chan error, numBlocks)

	maxWorkers := min(numBlocks, 8)
	blocksCh := make(chan int, numBlocks)

	for i := 0; i < numBlocks; i++ {
		blocksCh <- i
	}
	close(blocksCh)

	for w := 0; w < maxWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for blockIdx := range blocksCh {
				select {
				case <-ctx.Done():
					errCh <- ctx.Err()
					return
				default:
				}

				blockCounter := make([]byte, cc.blockSize)
				copy(blockCounter, counter)
				incrementCounter(blockCounter, blockIdx)

				encrypted, err := cc.cipher.Encrypt(blockCounter)
				if err != nil {
					errCh <- err
					return
				}

				start := blockIdx * cc.blockSize
				end := min(start+cc.blockSize, len(data))
				for j := start; j < end; j++ {
					ciphertext[j] = data[j] ^ encrypted[j-start]
				}
			}
		}()
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		if err != nil {
			return nil, err
		}
	}

	return ciphertext, nil
}

func (cc *CipherContext) decryptCTR(ctx context.Context, data []byte) ([]byte, error) {
	return cc.encryptCTR(ctx, data)
}

func (cc *CipherContext) encryptRandomDelta(ctx context.Context, data []byte) ([]byte, error) {
	if len(data)%cc.blockSize != 0 {
		return nil, errors.New("data length must be multiple of block size")
	}

	numBlocks := len(data) / cc.blockSize
	ciphertext := make([]byte, len(data)+numBlocks*cc.blockSize)

	for i := 0; i < numBlocks; i++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		start := i * cc.blockSize
		end := start + cc.blockSize
		block := make([]byte, cc.blockSize)
		copy(block, data[start:end])

		delta := make([]byte, cc.blockSize)
		if _, err := io.ReadFull(rand.Reader, delta); err != nil {
			return nil, err
		}

		XorBytes(block, delta)

		encrypted, err := cc.cipher.Encrypt(block)
		if err != nil {
			return nil, err
		}

		outStart := i * (cc.blockSize * 2)
		copy(ciphertext[outStart:outStart+cc.blockSize], encrypted)
		copy(ciphertext[outStart+cc.blockSize:outStart+cc.blockSize*2], delta)
	}

	return ciphertext, nil
}

func (cc *CipherContext) decryptRandomDelta(ctx context.Context, data []byte) ([]byte, error) {
	if len(data)%(cc.blockSize*2) != 0 {
		return nil, errors.New("ciphertext length must be multiple of 2*block size")
	}

	numBlocks := len(data) / (cc.blockSize * 2)
	plaintext := make([]byte, numBlocks*cc.blockSize)

	for i := 0; i < numBlocks; i++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		inStart := i * (cc.blockSize * 2)
		encryptedBlock := data[inStart : inStart+cc.blockSize]
		delta := data[inStart+cc.blockSize : inStart+cc.blockSize*2]

		decrypted, err := cc.cipher.Decrypt(encryptedBlock)
		if err != nil {
			return nil, err
		}

		XorBytes(decrypted, delta)

		outStart := i * cc.blockSize
		copy(plaintext[outStart:outStart+cc.blockSize], decrypted)
	}

	return plaintext, nil
}

func (cc *CipherContext) applyPadding(data []byte) ([]byte, error) {
	paddingLen := cc.blockSize - (len(data) % cc.blockSize)
	if paddingLen == 0 {
		paddingLen = cc.blockSize
	}

	padded := make([]byte, len(data)+paddingLen)
	copy(padded, data)

	switch cc.padding {
	case Zeros:

	case ANSIX923:
		padded[len(padded)-1] = byte(paddingLen)

	case PKCS7:
		for i := len(data); i < len(padded); i++ {
			padded[i] = byte(paddingLen)
		}

	case ISO10126:
		if paddingLen > 1 {
			randomBytes := padded[len(data) : len(padded)-1]
			if _, err := io.ReadFull(rand.Reader, randomBytes); err != nil {
				return nil, fmt.Errorf("failed to generate random padding: %w", err)
			}
		}
		padded[len(padded)-1] = byte(paddingLen)

	default:
		return nil, fmt.Errorf("unsupported padding mode: %v", cc.padding)
	}

	return padded, nil
}

func (cc *CipherContext) removePadding(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("cannot remove padding from empty data")
	}

	if len(data)%cc.blockSize != 0 {
		return nil, errors.New("data length must be multiple of block size")
	}

	switch cc.padding {
	case Zeros:
		i := len(data) - 1
		for i >= 0 && data[i] == 0 {
			i--
		}
		return data[:i+1], nil

	case ANSIX923, ISO10126:
		paddingLen := int(data[len(data)-1])
		if paddingLen > cc.blockSize || paddingLen > len(data) {
			return nil, errors.New("invalid padding length")
		}
		return data[:len(data)-paddingLen], nil

	case PKCS7:
		paddingLen := int(data[len(data)-1])
		if paddingLen > cc.blockSize || paddingLen > len(data) {
			return nil, errors.New("invalid padding length")
		}

		for i := len(data) - paddingLen; i < len(data); i++ {
			if data[i] != byte(paddingLen) {
				return nil, errors.New("invalid PKCS7 padding")
			}
		}
		return data[:len(data)-paddingLen], nil

	default:
		return nil, fmt.Errorf("unsupported padding mode: %v", cc.padding)
	}
}

func XorBytes(a, b []byte) {
	for i := 0; i < len(a) && i < len(b); i++ {
		a[i] ^= b[i]
	}
}

func incrementCounter(counter []byte, value int) {
	carry := value
	for i := len(counter) - 1; i >= 0 && carry > 0; i-- {
		sum := int(counter[i]) + carry
		counter[i] = byte(sum % 256)
		carry = sum / 256
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

type SimpleCipher struct {
	roundKeys   [][]byte
	blockSize   int
	expander    KeyExpander
	transformer RoundTransformer
}

func NewSimpleCipher(blockSize int, expander KeyExpander, transformer RoundTransformer) *SimpleCipher {
	return &SimpleCipher{
		blockSize:   blockSize,
		expander:    expander,
		transformer: transformer,
	}
}

func (sc *SimpleCipher) SetKey(key []byte) error {
	roundKeys, err := sc.expander.ExpandKey(key)
	if err != nil {
		return err
	}
	sc.roundKeys = roundKeys
	return nil
}

func (sc *SimpleCipher) Encrypt(block []byte) ([]byte, error) {
	if len(block) != sc.blockSize {
		return nil, fmt.Errorf("block size must be %d bytes", sc.blockSize)
	}

	result := make([]byte, sc.blockSize)
	copy(result, block)

	for _, roundKey := range sc.roundKeys {
		var err error
		result, err = sc.transformer.Transform(result, roundKey)
		if err != nil {
			return nil, err
		}
	}

	return result, nil
}

func (sc *SimpleCipher) Decrypt(block []byte) ([]byte, error) {
	if len(block) != sc.blockSize {
		return nil, fmt.Errorf("block size must be %d bytes", sc.blockSize)
	}

	result := make([]byte, sc.blockSize)
	copy(result, block)

	for i := len(sc.roundKeys) - 1; i >= 0; i-- {
		var err error
		result, err = sc.transformer.Transform(result, sc.roundKeys[i])
		if err != nil {
			return nil, err
		}
	}

	return result, nil
}

func (sc *SimpleCipher) BlockSize() int {
	return sc.blockSize
}

type SimpleKeyExpander struct{}

func (ske *SimpleKeyExpander) ExpandKey(key []byte) ([][]byte, error) {
	roundKeys := make([][]byte, 10)
	for i := range 10 {
		roundKey := make([]byte, len(key))
		copy(roundKey, key)
		for j := range roundKey {
			roundKey[j] ^= byte(i + 1)
		}
		roundKeys[i] = roundKey
	}
	return roundKeys, nil
}

type SimpleRoundTransformer struct{}

func (srt *SimpleRoundTransformer) Transform(block, roundKey []byte) ([]byte, error) {
	result := make([]byte, len(block))
	for i := range block {
		result[i] = block[i] ^ roundKey[i%len(roundKey)]
	}
	return result, nil
}

/*func main() {
	exp := &SimpleKeyExpander{}
	tr := &SimpleRoundTransformer{}
	cipher := NewSimpleCipher(16, exp, tr)

	cfg := CipherContextConfig{
		Key:     []byte("demo_key_123456"),
		Mode:    CTR,
		Padding: PKCS7,
	}
	ctx, _ := context.WithCancel(context.Background())
	cc, _ := NewCipherContext(cipher, cfg)

	plain := []byte("demo data")
	enc, _ := cc.EncryptBytes(ctx, plain)
	dec, _ := cc.DecryptBytes(ctx, enc)

	fmt.Printf("plain → %q\nenc   → %x\ndec   → %q\n",
		plain, enc, dec)

	_ = os.WriteFile("in.txt", []byte("file demo content"), 0644)
	_ = cc.EncryptFile(ctx, "in.txt", "encrypted.txt")
	_ = cc.DecryptFile(ctx, "encrypted.txt", "out.txt")

	decryptedFile, _ := os.ReadFile("out.txt")
	fmt.Printf("file decrypted: %q\n", decryptedFile)
}*/
