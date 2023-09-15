package kgen_test

import (
	"fmt"
	"math/big"
	"os"
	"testing"

	"github.com/joumanae/kgen"
	"github.com/rogpeppe/go-internal/testscript"
)

func FuzzTestPublicKey(f *testing.F) {
	f.Fuzz(func(t *testing.T, modulus int, base int, secretKey int) {
		kgen.PublicKey(base, modulus, secretKey)
	})
}

func FuzzTestSharedKey(f *testing.F) {
	f.Fuzz(func(t *testing.T, modulus int, base int, secret int, secret2 int) {

		if modulus == 0 || base == 0 {
			t.Skip()
		}

		pk1, err := kgen.PublicKey(base, modulus, secret)
		if err != nil {
			t.Fatal(err)
		}
		pk2, err := kgen.PublicKey(base, modulus, secret2)
		if err != nil {
			t.Fatal(err)
		}
		key1, err := kgen.SharedKey(pk2, secret, modulus)
		if err != nil {
			t.Errorf("error %v", err)
		}

		key2, err := kgen.SharedKey(pk1, secret2, modulus)
		if err != nil {
			t.Errorf("error %v", err)
		}

		if key1.Cmp(key2) != 0 {
			t.Errorf("the two users do not have the same shared key: key 1: %v, key 2: %v", key1, key2)
		}
	})
}

func TestParseBigInt(t *testing.T) {

	got, ok := kgen.ParseBigInt("52")
	want := big.NewInt(52)
	if !ok {
		t.Fatal("problem parsing")
	}
	// cmp method
	if got.Cmp(want) != 0 {
		t.Errorf("want %v, got %v", want, got)
	}
}

func TestScript(t *testing.T) {
	testscript.Run(t, testscript.Params{
		Dir: "testdata/script",
	})
}

func TestMain(m *testing.M) {
	os.Exit(testscript.RunMain(m, map[string]func() int{
		"kgen": kgen.Main,
	}))
}

func TestPowerCalculatesTheBigIntToThePowerOfInt(t *testing.T) {
	w := big.NewInt(int64(10000))
	base := big.NewInt(int64(10))
	g := kgen.Power(base, 4)
	if w.Cmp(g) != 0 {
		t.Errorf("want %v, got %v", w, g)
	}
}

func TestSecretKeyOnceGeneratedIsGreaterThanOne(t *testing.T) {
	got := kgen.GenerateSecretKey()
	if got <= 1 {
		t.Error("Cannot have a generated secret key that is inferior to 1")
	}
}

func TestThatPublicKeyCalculatesPublicKeyPerDHRules(t *testing.T) {
	want := big.NewInt(int64(5))
	got, err := kgen.PublicKey(5, 13, 5)
	if err != nil {
		t.Error(err)
	}
	if want.Cmp(got) != 0 {
		t.Errorf("want %v, got %v", want, got)

	}
}

func TestSharedKey(t *testing.T) {
	// need to figure out what is the equivalent of 368 in int64
	publicKey := big.NewInt(int64(3))
	want := big.NewInt(int64(9))
	got, err := kgen.SharedKey(publicKey, 368, 13)
	if err != nil {
		t.Error(err)
	}
	if want.Cmp(got) != 0 {
		t.Errorf("want %v, got %v", want, got)
	}
}

func ExamplePower() {
	base := big.NewInt(int64(10))
	fmt.Println(kgen.Power(base, 2))
	// Output:
	// 100
}
