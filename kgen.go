package kgen

import (
	"errors"
	"flag"
	"fmt"
	"math/big"
	"math/rand"
	"os"
)

var ErrZeroOrNegativeModulus = errors.New("the modulus cannot be 0 or negative")
var ErrZeroOrNegativeBase = errors.New("the base cannot be 0 or negative")

// GenerateSecretKey is a function that gnerates a random secret key
func GenerateSecretKey() int {
	secret := rand.Intn(1000) + 1
	return secret
}

// Power is a function that calculates  a *big.Int  to the power of a number and return a *big.Int
func Power(base *big.Int, x int) *big.Int {
	result := big.NewInt(1)
	for i := 0; i < x; i++ {
		result.Mul(result, base)
	}
	return result
}

// ParseBigInt parses a string and return a *big.Int
func ParseBigInt(s string) (*big.Int, bool) {
	n := new(big.Int)
	return n.SetString(s, 10)
}

// PublicKey is a function that calculates the public key
func PublicKey(base int, modulus int, secretKey int) (*big.Int, error) {
	if modulus == 0 || modulus < 0 {
		return nil, ErrZeroOrNegativeModulus
	}
	if base == 0 || base < 0 {
		return nil, ErrZeroOrNegativeBase
	}

	p := Power(big.NewInt(int64(base)), secretKey)
	p.Mod(p, big.NewInt(int64(modulus)))
	return p, nil
}

// SharedKey is a function that calculate the shared key
func SharedKey(publicKey *big.Int, secret int, modulus int) (*big.Int, error) {
	if modulus == 0 || modulus < 0 {
		return nil, ErrZeroOrNegativeModulus
	}

	p := Power(publicKey, secret)
	p = p.Mod(p, big.NewInt(int64(modulus)))
	return p, nil
}

func Main() int {

	mod := flag.Int("modulus", 1, "The modulus is a prime number")
	base := flag.Int("base", 1, "base")
	pubKey := flag.String("publicKey", "", "This is the public key")
	secretKey := GenerateSecretKey()
	secret := flag.Int("secret", 1, "This is your secret key")

	if len(os.Args[1:]) < 1 {
		fmt.Fprintln(os.Stderr, "Usage: kgen [-modulus modulus] [-base base] [-publicKey publicKey] [-secret secret]")
		return 1
	}

	flag.Parse()

	if len(*pubKey) == 0 {

		pn1, err := PublicKey(*base, *mod, secretKey)
		if err != nil {
			if *mod <= 0 {
				fmt.Println("Modulus cannot be negative or equal to zero")
			}
			if *base <= 0 {
				fmt.Println("Base cannot be negative or equal to zero")
			}
			os.Exit(1)
		}
		fmt.Printf("This is your public key: %s, & this is your secret key %v.", pn1, secretKey)
	} else {
		pk, ok := ParseBigInt(*pubKey)
		if !ok {
			fmt.Println("Your public key is not valid")
			os.Exit(1)
		}

		sk, err := SharedKey(pk, *secret, *mod)
		if err != nil {
			fmt.Println("Modulus cannot be negative or equal to zero")
			os.Exit(1)
		}
		fmt.Printf("This is your shared key %s", sk)
	}

	return 0
}
