package digisig

import (
	"math/big"
	"testing"

	curve "github.com/dece2183/go-digisig/ellipticCurve"
	stribog "github.com/dece2183/go-stribog"
)

var testMessage = []byte("hello there!")

const (
	testParamP  = "57896044618658097711785492504343953926634992332820282019728792003956564821041"
	testParamA  = "7"
	testParamQ  = "57896044618658097711785492504343953927082934583725450622380973592137631069619"
	testParamPx = "2"
	testParamPy = "4018974056539037503335449422937059775635739389905545080690979365213431566280"

	testPrivateKey = "55441196065363246126355624130324183196576709222340016572108097750006097525544"
)

func TestSignature256(t *testing.T) {
	p, ok := new(big.Int).SetString(testParamP, 10)
	if !ok {
		t.Errorf("p parameter parse error")
	}

	a, ok := new(big.Int).SetString(testParamA, 10)
	if !ok {
		t.Errorf("a parameter parse error")
	}

	q, ok := new(big.Int).SetString(testParamQ, 10)
	if !ok {
		t.Errorf("q parameter parse error")
	}

	px, ok := new(big.Int).SetString(testParamPx, 10)
	if !ok {
		t.Errorf("Px parameter parse error")
	}

	py, ok := new(big.Int).SetString(testParamPy, 10)
	if !ok {
		t.Errorf("Py parameter parse error")
	}

	privateKey, ok := new(big.Int).SetString(testPrivateKey, 10)
	if !ok {
		t.Errorf("private key parameter parse error")
	}

	P := curve.Point{X: px, Y: py}
	hash256 := stribog.New256()

	signature := NewSignature(privateKey, p, a, q, P, hash256)
	publicKey := signature.GenerateKey()

	testSign, err := signature.Sign(testMessage)
	if err != nil {
		t.Errorf("signing failed: %s", err)
	}

	t.Logf("generated signature: %X", new(big.Int).SetBytes(testSign))
	t.Logf("generated public key: (%X, %X)", publicKey.X, publicKey.Y)

	validator := NewValidator(publicKey, p, a, q, P, hash256)

	// validate the unchanged message
	valid := validator.Validate(testMessage, testSign)
	if !valid {
		t.Errorf("unchanged message isn't valid")
	}

	// try to change message and validate
	testMessage = []byte("hello world!")
	valid = validator.Validate(testMessage, testSign)
	if valid {
		t.Errorf("wrong message is valid")
	}
}
