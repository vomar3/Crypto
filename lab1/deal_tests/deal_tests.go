package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"lab1/deal"
	"lab1/interfaces"
	"os"
	"path/filepath"
)

func testFile(cipher interfaces.BlockCipher, filePath, mode string, key []byte) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}

	padding := interfaces.PKCS7
	if mode == "CTR" || mode == "CFB" || mode == "OFB" {
		padding = interfaces.Zeros
	}

	config := interfaces.CipherContextConfig{
		Key:     key,
		Mode:    getModeFromString(mode),
		Padding: padding,
	}

	cc, err := interfaces.NewCipherContext(cipher, config)
	if err != nil {
		return err
	}

	ctx := context.Background()

	encrypted, err := cc.EncryptBytes(ctx, data)
	if err != nil {
		return err
	}

	decrypted, err := cc.DecryptBytes(ctx, encrypted)
	if err != nil {
		return err
	}

	match := len(data) == len(decrypted)
	if match {
		for i := range data {
			if data[i] != decrypted[i] {
				match = false
				break
			}
		}
	}

	fmt.Printf("%s: %d -> %d bytes [%v]\n", mode, len(data), len(encrypted), match)
	return nil
}

func getModeFromString(mode string) interfaces.CipherMode {
	switch mode {
	case "ECB":
		return interfaces.ECB
	case "CBC":
		return interfaces.CBC
	case "CTR":
		return interfaces.CTR
	case "CFB":
		return interfaces.CFB
	case "OFB":
		return interfaces.OFB
	case "PCBC":
		return interfaces.PCBC
	default:
		return interfaces.ECB
	}
}

func main() {
	dealCipher, err := deal.NewDEAL(6)
	if err != nil {
		panic(err)
	}

	key := []byte{
		0x01, 0x23, 0x45, 0x67,
		0x89, 0xAB, 0xCD, 0xEF,
		0xFE, 0xDC, 0xBA, 0x98,
		0x76, 0x54, 0x32, 0x10,
	}

	if err := dealCipher.SetKey(key); err != nil {
		panic(err)
	}

	dealWrapper := &DEALWrapper{deal: dealCipher}
	var cipher interfaces.BlockCipher = dealWrapper

	testFolder := "test_data"
	files, err := os.ReadDir(testFolder)
	if err != nil {
		fmt.Printf("Error reading test folder: %v\n", err)
		return
	}

	modes := []string{"ECB", "CBC", "CTR", "CFB", "OFB"}

	for _, file := range files {
		filePath := filepath.Join(testFolder, file.Name())
		fileInfo, _ := file.Info()

		fmt.Printf("\n%s (%d bytes):\n", file.Name(), fileInfo.Size())

		for _, mode := range modes {
			if err := testFile(cipher, filePath, mode, key); err != nil {
				fmt.Printf("%-4s: error - %v\n", mode, err)
			}
		}
	}

	fmt.Println("\nPseudorandom sequences:")
	sizes := []int{16, 64, 256, 1024}
	for _, size := range sizes {
		data := make([]byte, size)
		rand.Read(data)
		fmt.Printf("%d bytes:\n", size)
		for _, mode := range modes {
			padding := interfaces.PKCS7

			if mode == "CTR" || mode == "CFB" || mode == "OFB" {
				padding = interfaces.Zeros
			}

			config := interfaces.CipherContextConfig{
				Key:     key,
				Mode:    getModeFromString(mode),
				Padding: padding,
			}

			cc, _ := interfaces.NewCipherContext(cipher, config)
			ctx := context.Background()
			encrypted, _ := cc.EncryptBytes(ctx, data)
			decrypted, _ := cc.DecryptBytes(ctx, encrypted)

			match := len(data) == len(decrypted)
			if match {
				for i := range data {
					if data[i] != decrypted[i] {
						match = false
						break
					}
				}
			}

			fmt.Printf("  %s : %v\n", mode, match)
		}
	}
}

type DEALWrapper struct {
	deal *deal.DEAL
}

func (dw *DEALWrapper) SetKey(key []byte) error {
	return dw.deal.SetKey(key)
}

func (dw *DEALWrapper) Encrypt(block []byte) ([]byte, error) {
	return dw.deal.Encrypt(block)
}

func (dw *DEALWrapper) Decrypt(block []byte) ([]byte, error) {
	return dw.deal.Decrypt(block)
}

func (dw *DEALWrapper) BlockSize() int {
	return dw.deal.BlockSize()
}
