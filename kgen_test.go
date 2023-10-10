package kgen_test

import (
	"fmt"
	"math/big"
	"os"
	"testing"

	"github.com/joumanae/kgen"
	gabibig "github.com/privacybydesign/gabi/big"
	"github.com/rogpeppe/go-internal/testscript"
)

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
	want := big.NewInt(int64(1))
	modulus := big.NewInt(int64(13))
	got, err := kgen.PublicKey(1, modulus, 5)
	if err != nil {
		t.Error(err)
	}
	if want.Cmp(got) != 0 {
		t.Errorf("want %v, got %v", want, got)

	}
}

func TestSharedKey(t *testing.T) {
	publicKey := big.NewInt(int64(3))
	want := big.NewInt(int64(9))
	modulus := big.NewInt(int64(13))
	got, err := kgen.SharedKey(publicKey, 368, modulus)
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

func TestConvertToBigInt(t *testing.T) {
	_, err := kgen.ConvertToBigInt(gabibig.NewInt(0))
	if err == nil {
		t.Fatal("want error when modulus does not follow DH criteria")
	}
}
