package kgen

import (
	"errors"
	"flag"
	"fmt"
	"math/big"
	"math/rand"
	"os"

	"github.com/credentials/safeprime"
)

var ErrModulusTooSmall = errors.New("the modulus is under 256 bytes")
var ErrZeroOrNegativeBase = errors.New("the base cannot be 0 or negative")

// GenerateSecretKey is a function that gnerates a random secret key
func GenerateSecretKey() int {
	secret := rand.Intn(1000) + 1
	return secret
}

func GenerateModulus() (*big.Int, error) {
	m, err := safeprime.Generate(2048)
	if err != nil {
		return m, err
	}
	mstring := m.String()
	if len(mstring) < 256 {
		return m, ErrModulusTooSmall
	}
	return m, nil
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
func PublicKey(base int, modulus *big.Int, secretKey int) (*big.Int, error) {
	if base == 0 || base < 0 {
		return nil, ErrZeroOrNegativeBase
	}

	p := Power(big.NewInt(int64(base)), secretKey)
	m, err := GenerateModulus()
	if err != nil {
		panic(err)
	}
	p.Mod(p, m)
	return p, nil
}

// SharedKey is a function that calculate the shared key
func SharedKey(publicKey *big.Int, secret int, modulus *big.Int) (*big.Int, error) {

	p := Power(publicKey, secret)
	m, err := GenerateModulus()
	if err != nil {
		panic(err)
	}
	p.Mod(p, m)
	return p, nil
}

func Main() int {

	base := flag.Int("base", 1, "base")
	pubKey := flag.String("publicKey", "", "This is the public key")
	secretKey := GenerateSecretKey()
	modulus, err := GenerateModulus()
	if err != nil {
		panic(err)
	}
	secret := flag.Int("secret", 1, "This is your secret key")

	flag.Parse()
	if len(*pubKey) == 0 {

		pn1, err := PublicKey(*base, modulus, secretKey)
		if err != nil {
			fmt.Printf("an error occured %s", err)
			os.Exit(1)
		}

		if len(os.Args[1:]) < 1 {
			fmt.Fprintf(os.Stdout,
				`
			This is your public key: %s, & this is your secret key %v.\n,
			Kgen automatically generates a public key for you. 
			If you wanted to specify your own modulus, base or public key, 
			take a look at the usage: kgen [-modulus modulus] [-base base] [-publicKey publicKey] [-secret secret]
			`,
				pn1, secretKey)
		}
	} else {
		pk, ok := ParseBigInt(*pubKey)
		if !ok {
			fmt.Println("Your public key is not valid")
			os.Exit(1)
		}

		sk, err := SharedKey(pk, *secret, modulus)
		if err != nil {
			fmt.Println("Modulus cannot be negative or equal to zero")
			os.Exit(1)
		}
		fmt.Printf("This is your shared key %s", sk)
	}
	return 0
}
