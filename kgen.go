package kgen

import (
	"errors"
	"flag"
	"fmt"
	"math/big"
	"math/rand"
	"os"

	gabibig "github.com/privacybydesign/gabi/big"
	"github.com/privacybydesign/gabi/safeprime"
)

var ErrModulusTooSmall = errors.New("the modulus is under 256 bytes")
var ErrZeroOrNegativeBase = errors.New("the base cannot be 0 or negative")

// GenerateSecretKey is a function that gnerates a random secret key
func GenerateSecretKey() int {
	secret := rand.Intn(1000) + 1
	return secret
}

func MustGenerateModulus() *big.Int {
	modulus, err := safeprime.Generate(2048, nil)

	if err != nil {
		panic(err)
	}
	m, err := ConvertToBigInt(modulus)
	if err != nil {
		panic(err)
	}
	return m
}

// IsGreaterThan256Bytes checks that the modulus is greater
// true and the error is nil
// false and an error

func ConvertToBigInt(modulus *gabibig.Int) (*big.Int, error) {

	if len(modulus.Bytes()) < 256 {
		return nil, errors.New("the modulus is under 256 bytes")
	}
	fmt.Printf("modulus %v", modulus.Go())
	return modulus.Go(), nil
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
	m := MustGenerateModulus()

	p.Mod(p, m)
	return p, nil
}

// SharedKey is a function that calculate the shared key
func SharedKey(publicKey *big.Int, secret int, modulus *big.Int) (*big.Int, error) {

	p := Power(publicKey, secret)
	m := MustGenerateModulus()
	p.Mod(p, m)
	return p, nil
}

func Main() int {

	base := 2
	pubKey := flag.String("publicKey", "", "This is the public key")
	secretKey := GenerateSecretKey()
	modulus := MustGenerateModulus()
	secret := flag.Int("secret", 1, "This is your secret key")

	flag.Parse()
	if len(*pubKey) == 0 {

		pn1, err := PublicKey(base, modulus, secretKey)
		if err != nil {
			fmt.Printf("an error occured %s", err)
			os.Exit(1)
		}

		if len(os.Args[1:]) < 1 {
			fmt.Fprintf(os.Stdout,
				`
			This is your public key: %s, & this is your secret key %v.\n,
			Kgen automatically generates a public key for you. 
			It also generates the modulus and the base for you. 
			Once your public key is generated, use the public key flag to get your 
			shared secret key. 
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
