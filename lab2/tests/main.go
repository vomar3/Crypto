package main

import (
	"fmt"
	"lab2/primalityTest"
	"lab2/rsaService"
	"lab2/statelessService"
	"lab2/wienerAttack"
	"math/big"
)

func main() {
	Task1()
	Task2()
	Task3()
	Task4()
}

func Task1() {
	a, b := big.NewInt(48), big.NewInt(18)
	gcdRes, err := statelessService.GCD(a, b)
	if err != nil {
		fmt.Printf("%v\n", err)
	} else {
		fmt.Printf("НОД(%s, %s) = %s\n", a, b, gcdRes)
	}

	fmt.Println("Расширенный НОД")
	a2, b2 := big.NewInt(240), big.NewInt(46)
	gcd, x, y, err := statelessService.ExtendedGCD(a2, b2)
	if err != nil {
		fmt.Printf("ExtendedGCD: %v\n", err)
	} else {
		fmt.Printf("НОД(%s, %s) = %s, x=%s, y=%s\n", a2, b2, gcd, x, y)
	}

	fmt.Println("Возведение в степень по модулю")
	modPowRes, err := statelessService.ModPow(big.NewInt(3), big.NewInt(7), big.NewInt(13))
	if err != nil {
		fmt.Printf("%v\n", err)
	} else {
		fmt.Printf("3^7 mod 13 = %s\n", modPowRes)
	}

	fmt.Print("Символ Лежандра: (2/7) = ")
	legRes, err := statelessService.Legendre(big.NewInt(2), big.NewInt(7))
	if err != nil {
		fmt.Printf("%v\n", err)
	} else {
		fmt.Println(legRes)
	}

	fmt.Print("Символ Якоби: (2/15) = ")
	jacRes, err := statelessService.Jacobi(big.NewInt(2), big.NewInt(15))
	if err != nil {
		fmt.Printf("%v\n", err)
	} else {
		fmt.Println(jacRes)
	}
}

func Task2() {
	fermat := primalityTest.NewFermatTest()
	solovay := primalityTest.NewSolovayStrassenTest()
	miller := primalityTest.NewMillerRabinTest()

	tests := []primalityTest.PrimalityTester{fermat, solovay, miller}

	testNumbers := []*big.Int{
		big.NewInt(17),
		big.NewInt(97),
		big.NewInt(561),
	}

	for _, n := range testNumbers {
		fmt.Printf("\nЧисло: %s\n", n)
		for _, test := range tests {
			result, err := test.IsProbablyPrime(n, 0.99)
			if err != nil {
				fmt.Printf("%s: %v\n", test.GetTestName(), err)
				continue
			}

			status := "Простое"
			if !result {
				status = "Составное"
			}
			fmt.Printf("%s: %s\n", test.GetTestName(), status)
		}
	}
}

func Task3() {
	rsa, err := rsaService.NewRSAService(rsaService.MillerRabin, 0.99, 1024)
	if err != nil {
		fmt.Printf("%v\n", err)
		return
	}

	err = rsa.GenerateKeys()
	if err != nil {
		fmt.Printf("%v\n", err)
		return
	}

	message := big.NewInt(4243743827348237483)
	fmt.Printf("Исходное сообщение: %s\n", message)

	ciphertext, err := rsa.Encrypt(message)
	if err != nil {
		fmt.Printf("%v\n", err)
		return
	}
	fmt.Printf("Зашифрованное: %s\n", ciphertext)

	decrypted, err := rsa.Decrypt(ciphertext)
	if err != nil {
		fmt.Printf("%v\n", err)
		return
	}
	fmt.Printf("Расшифрованное: %s\n", decrypted)

	if message.Cmp(decrypted) == 0 {
		fmt.Println("Шифрование и дешифрование работает корректно")
	}

	fmt.Println()
}

func Task4() {
	wienerSvc := wienerAttack.NewWienerAttackService()

	rsaSvc, err := rsaService.NewRSAService(
		rsaService.MillerRabin,
		0.99,
		2048,
	)
	if err != nil {
		fmt.Printf("%v\n", err)
		return
	}

	err = rsaSvc.GenerateKeys()
	if err != nil {
		fmt.Printf("%v\n", err)
		return
	}

	fmt.Println("Ключи успешно сгенерированы")
	fmt.Println(rsaSvc.GetKeyInfo())

	pubKey, err := rsaSvc.GetPublicKey()
	if err != nil {
		fmt.Printf("%v\n", err)
		return
	}

	fmt.Println("Попытка осуществить атаку Винера на защищенный ключ")
	result1, err := wienerSvc.Attack(pubKey.E, pubKey.N)
	if err != nil {
		fmt.Printf("%v\n", err)
	} else {
		PrintResult(result1)

		if !result1.Success {
			fmt.Println("Ключ защищен")
		} else {
			fmt.Println("Ключ оказался уязвимым")
		}
	}

	fmt.Println("Атака на уязвимый ключ:")
	fmt.Println("Создаем специальный уязвимый ключ с малым d")

	vulnerable := createVulnerableRSAKey()

	fmt.Printf("Уязвимый публичный ключ:\n")
	fmt.Printf("N = %s\n", vulnerable.N)
	fmt.Printf("e = %s\n", vulnerable.E)
	fmt.Printf("(битовая длина N: %d бит)\n", vulnerable.N.BitLen())

	fmt.Printf("Секретная информация:\n")
	fmt.Printf("d = %s\n", vulnerable.D)
	fmt.Printf("phi(N) = %s\n", vulnerable.Phi)
	fmt.Printf("p = %s\n", vulnerable.P)
	fmt.Printf("q = %s\n", vulnerable.Q)
	fmt.Printf("(битовая длина d: %d бит)\n", vulnerable.D.BitLen())

	fmt.Println("\nПроверка корректности уязвимого ключа:")

	gcd, err := statelessService.GCD(vulnerable.E, vulnerable.Phi)
	if err != nil {
		fmt.Printf("%v\n", err)
		return
	}
	if gcd.Cmp(big.NewInt(1)) == 0 {
		fmt.Println("GCD(e, phi(N)) = 1")
	} else {
		fmt.Printf("%s", gcd)
	}

	check := new(big.Int).Mul(vulnerable.E, vulnerable.D)
	check.Mod(check, vulnerable.Phi)
	if check.Cmp(big.NewInt(1)) == 0 {
		fmt.Println("e*d ≡ 1 mod phi(N)")
	} else {
		fmt.Printf("e*d ≡ 1 mod phi(N) (получено %s)\n", check)
	}

	testMsg := big.NewInt(42)
	if testMsg.Cmp(vulnerable.N) >= 0 {
		testMsg = big.NewInt(17)
	}

	fmt.Printf("Тестовое сообщение: %s\n", testMsg)

	encrypted, err := statelessService.ModPow(testMsg, vulnerable.E, vulnerable.N)
	if err != nil {
		fmt.Printf("%v\n", err)
		return
	}

	decrypted, err := statelessService.ModPow(encrypted, vulnerable.D, vulnerable.N)
	if err != nil {
		fmt.Printf("%v\n", err)
		return
	}

	if testMsg.Cmp(decrypted) == 0 {
		fmt.Println("Тест шифрования/дешифрования:")
	} else {
		fmt.Printf("Тест шифрования/дешифрования: (получено %s)\n", decrypted)
	}

	result2, err := wienerSvc.Attack(vulnerable.E, vulnerable.N)
	if err != nil {
		fmt.Printf("%v\n", err)
		return
	}

	PrintResult(result2)

	if result2.Success {
		fmt.Println("Проверка найденных значений:")

		matches := 0
		totalChecks := 0

		totalChecks++
		if result2.D.Cmp(vulnerable.D) == 0 {
			fmt.Println("Найденное d совпадает с оригинальным!")
			matches++
		} else {
			fmt.Printf("Найденное d не совпадает: найдено %s, оригинал %s\n",
				result2.D, vulnerable.D)
		}

		totalChecks++
		if result2.Phi.Cmp(vulnerable.Phi) == 0 {
			fmt.Println("Найденное phi(N) совпадает с оригинальным!")
			matches++
		} else {
			fmt.Printf("Найденное phi(N) не совпадает: найдено %s, оригинал %s\n",
				result2.Phi, vulnerable.Phi)
		}

		totalChecks++
		if result2.P != nil && result2.Q != nil {
			pMatches := (result2.P.Cmp(vulnerable.P) == 0 && result2.Q.Cmp(vulnerable.Q) == 0) ||
				(result2.P.Cmp(vulnerable.Q) == 0 && result2.Q.Cmp(vulnerable.P) == 0)

			if pMatches {
				fmt.Println("Найденные p и q совпадают с оригинальными!")
				matches++
			} else {
				fmt.Printf("Найденные p и q не совпадают: найдено (%s, %s), оригинал (%s, %s)\n",
					result2.P, result2.Q, vulnerable.P, vulnerable.Q)
			}
		}

		totalChecks++
		testMessage := big.NewInt(42)
		if testMessage.Cmp(vulnerable.N) >= 0 {
			testMessage = big.NewInt(17)
		}

		encrypted, err := statelessService.ModPow(testMessage, vulnerable.E, vulnerable.N)
		if err != nil {
			fmt.Printf("%v\n", err)
		} else {
			decrypted, err := statelessService.ModPow(encrypted, result2.D, vulnerable.N)
			if err != nil {
				fmt.Printf("%v\n", err)
			} else if testMessage.Cmp(decrypted) == 0 {
				fmt.Println("Дешифрование найденным d успешно!")
				matches++
			} else {
				fmt.Printf("Дешифрование не удалось: получено %s\n", decrypted)
			}
		}

		if matches >= 3 {
			fmt.Println("Атака Винера успешна! Ключ взломан!")
		}
	}
}

func PrintResult(result *wienerAttack.WienerResult) {
	fmt.Println("Результат атаки Винера")

	if result.Success {
		fmt.Println("Атака успешна!")
		fmt.Printf("\nНайденная приватная экспонента d:\n   %s\n", result.D.String())
		fmt.Printf("\nФункция Эйлера phi(N):\n   %s\n", result.Phi.String())

		if result.P != nil && result.Q != nil {
			fmt.Printf("Восстановленные простые числа:\n")
			fmt.Printf("p = %s\n", result.P.String())
			fmt.Printf("q = %s\n", result.Q.String())

			product := new(big.Int).Mul(result.P, result.Q)
			fmt.Printf("p * q = %s (проверка)\n", product.String())
		}

		fmt.Printf("Битовая длина d: %d бит\n", result.D.BitLen())
		fmt.Printf("Битовая длина phi(N): %d бит\n", result.Phi.BitLen())
	} else {
		fmt.Println("Атака не удалась")
	}

	fmt.Printf("\n%s\n", result.Message)

	fmt.Printf("Всего вычислено подходящих дробей: %d\n", len(result.Convergents))
	fmt.Println("Список подходящих дробей (convergents):")

	maxDisplay := 20
	for i, conv := range result.Convergents {
		if i < maxDisplay || i >= len(result.Convergents)-5 {
			fmt.Printf("%s\n", conv.String())
		} else if i == maxDisplay {
			fmt.Printf("(пропущено %d дробей)\n", len(result.Convergents)-maxDisplay-5)
		}
	}
}

type VulnerableKey struct {
	N, E, D, Phi, P, Q *big.Int
}

func createVulnerableRSAKey() *VulnerableKey {
	p := big.NewInt(239)
	q := big.NewInt(379)

	N := new(big.Int).Mul(p, q)

	pMinus1 := new(big.Int).Sub(p, big.NewInt(1))
	qMinus1 := new(big.Int).Sub(q, big.NewInt(1))
	phi := new(big.Int).Mul(pMinus1, qMinus1)

	d := big.NewInt(5)
	e := big.NewInt(17993)

	check := new(big.Int).Mul(e, d)
	check.Mod(check, phi)
	if check.Cmp(big.NewInt(1)) != 0 {
		panic("Создан некорректный уязвимый ключ: e*d != 1 mod phi(N)")
	}

	return &VulnerableKey{
		N:   N,
		E:   e,
		D:   d,
		Phi: phi,
		P:   p,
		Q:   q,
	}
}
