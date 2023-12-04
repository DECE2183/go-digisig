package digisig

import (
	"crypto/rand"
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
	testPublicKeyX = "57520216126176808443631405023338071176630104906313632182896741342206604859403"
	testPublicKeyY = "17614944419213781543809391949654080031942662045363639260709847859438286763994"
)

func TestSignature256(t *testing.T) {
	p, ok := new(big.Int).SetString(testParamP, 10)
	if !ok {
		t.Errorf("p parameter parse error")
		return
	}

	a, ok := new(big.Int).SetString(testParamA, 10)
	if !ok {
		t.Errorf("a parameter parse error")
		return
	}

	q, ok := new(big.Int).SetString(testParamQ, 10)
	if !ok {
		t.Errorf("q parameter parse error")
		return
	}

	px, ok := new(big.Int).SetString(testParamPx, 10)
	if !ok {
		t.Errorf("Px parameter parse error")
		return
	}

	py, ok := new(big.Int).SetString(testParamPy, 10)
	if !ok {
		t.Errorf("Py parameter parse error")
		return
	}

	privateKey, ok := new(big.Int).SetString(testPrivateKey, 10)
	if !ok {
		t.Errorf("private key parameter parse error")
		return
	}

	publicKeyX, ok := new(big.Int).SetString(testPublicKeyX, 10)
	if !ok {
		t.Errorf("private key parameter parse error")
		return
	}

	publicKeyY, ok := new(big.Int).SetString(testPublicKeyY, 10)
	if !ok {
		t.Errorf("private key parameter parse error")
		return
	}

	P := curve.Point{X: px, Y: py}
	hash256 := stribog.New256()

	signature := NewSignature(privateKey, p, a, q, P, hash256)
	publicKey := signature.GenerateKey()
	t.Logf("generated public key: (%X, %X)", publicKey.X, publicKey.Y)

	if publicKeyX.Cmp(publicKey.X) != 0 || publicKeyY.Cmp(publicKey.Y) != 0 {
		t.Errorf("public key mismatch")
		return
	}

	testSign, err := signature.Sign(testMessage)
	if err != nil {
		t.Errorf("signing failed: %s", err)
		return
	}
	t.Logf("generated signature: %X", new(big.Int).SetBytes(testSign))

	validator := NewValidator(publicKey, p, a, q, P, hash256)

	// validate the unchanged message
	valid := validator.Validate(testMessage, testSign)
	if !valid {
		t.Errorf("unchanged message isn't valid")
		return
	}

	// try to change message and validate
	testMessage = []byte("hello world!")
	valid = validator.Validate(testMessage, testSign)
	if valid {
		t.Errorf("wrong message is valid")
		return
	}
}

const (
	testCustomParamP  = "6277101735386680763835789423207666416083908700390324961279"
	testCustomParamA  = "-3"
	testCustomParamQ  = "6277101735386680763835789423176059013767194773182842284081"
	testCustomParamPx = "602046282375688656758213480587526111916698976636884684818"
	testCustomParamPy = "174050332293622031404857552280219410364023488927386650641"
)

func TestSignatureCustom(t *testing.T) {
	p, ok := new(big.Int).SetString(testCustomParamP, 10)
	if !ok {
		t.Errorf("p parameter parse error")
		return
	}

	a, ok := new(big.Int).SetString(testCustomParamA, 10)
	if !ok {
		t.Errorf("a parameter parse error")
		return
	}

	q, ok := new(big.Int).SetString(testCustomParamQ, 10)
	if !ok {
		t.Errorf("q parameter parse error")
		return
	}

	px, ok := new(big.Int).SetString(testCustomParamPx, 10)
	if !ok {
		t.Errorf("Px parameter parse error")
		return
	}

	py, ok := new(big.Int).SetString(testCustomParamPy, 10)
	if !ok {
		t.Errorf("Py parameter parse error")
		return
	}

	privateKey, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 256))
	if err != nil {
		t.Errorf("random failed: %s", err)
		return
	}
	t.Logf("generated private key: %X", privateKey)

	P := curve.Point{X: px, Y: py}
	hash256 := stribog.New256()

	signature := NewSignature(privateKey, p, a, q, P, hash256)
	publicKey := signature.GenerateKey()
	t.Logf("generated public key: (%X, %X)", publicKey.X, publicKey.Y)

	testSign, err := signature.Sign(testMessage)
	if err != nil {
		t.Errorf("signing failed: %s", err)
		return
	}
	t.Logf("generated signature: %X", new(big.Int).SetBytes(testSign))

	validator := NewValidator(publicKey, p, a, q, P, hash256)

	// validate the unchanged message
	valid := validator.Validate(testMessage, testSign)
	if !valid {
		t.Errorf("unchanged message isn't valid")
		return
	}

	// try to change message and validate
	testMessage = []byte("hello world!")
	valid = validator.Validate(testMessage, testSign)
	if valid {
		t.Errorf("wrong message is valid")
		return
	}
}
