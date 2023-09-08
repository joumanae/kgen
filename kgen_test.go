package kgen_test

import (
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

func TestPower(t *testing.T) {

}
