package digisig

import (
	"crypto/rand"
	"hash"
	"math/big"

	curve "github.com/dece2183/go-digisig/ellipticCurve"
)

type Signature struct {
	// external parameters
	key      *big.Int // (d)
	p, a, q  *big.Int
	_P       curve.Point
	hashFunc hash.Hash
	// internal variables
	blockSize int
	curve     *curve.Curve
}

func NewSignature(privateKey, p, a, q *big.Int, P curve.Point, hashFunc hash.Hash) *Signature {
	s := &Signature{
		key:       privateKey,
		p:         p,
		a:         a,
		q:         q,
		_P:        P,
		hashFunc:  hashFunc,
		blockSize: hashFunc.BlockSize(),
		curve:     curve.NewCurve(p, a),
	}
	return s
}

// GenerateKey generates the validation key based on the parameters passed in NewSignature.
//
// Generated key should be provided to the Validator.
func (s *Signature) GenerateKey() curve.Point {
	return s.curve.Scalar(s.key, s._P)
}

// Sign generates the digital signature for the provided message.
//
// This function returns only signature without message.
func (s *Signature) Sign(msg []byte) ([]byte, error) {
	s.hashFunc.Reset()
	s.hashFunc.Write(msg)

	hs := new(big.Int).SetBytes(s.hashFunc.Sum([]byte{}))

	var e, k, r, _s *big.Int
	var c curve.Point
	var err error
	e = s.calcE(hs)

recalculate:
	k, err = s.randK()
	if k == nil {
		return nil, err
	}

	c = s.genC(k)

	r = s.calcR(c)
	if r == nil {
		goto recalculate
	}

	_s = s.calcS(e, k, r)
	if _s == nil {
		goto recalculate
	}

	return append(s.completion(r), s.completion(_s)...), nil
}

func (s *Signature) calcE(hs *big.Int) *big.Int {
	e := hs.Mod(hs, s.q)
	if e.Cmp(big.NewInt(0)) == 0 {
		return big.NewInt(1)
	}
	return e
}

func (s *Signature) randK() (*big.Int, error) {
	var err error

	k := big.NewInt(1)
	max := big.NewInt(1).Lsh(k, uint(len(s.q.Bytes()))*8)

	for {
		k, err = rand.Int(rand.Reader, max)
		if err != nil {
			return nil, err
		}
		if k.Cmp(s.q) < 0 {
			return k, nil
		}
	}
}

func (s *Signature) genC(k *big.Int) curve.Point {
	return s.curve.Scalar(k, s._P)
}

func (s *Signature) calcR(c curve.Point) *big.Int {
	// c.X % s.q
	r := new(big.Int).Mod(c.X, s.q)
	if r.Cmp(big.NewInt(0)) == 0 || len(r.Bytes()) > s.blockSize {
		return nil
	}
	return r
}

func (s *Signature) calcS(e, k, r *big.Int) *big.Int {
	// _s = (r * s.key + k * e) % s.q;
	_s := new(big.Int).Mul(r, s.key)
	_s = _s.Add(_s, new(big.Int).Mul(k, e))
	_s = _s.Mod(_s, s.q)
	if _s.Cmp(big.NewInt(0)) == 0 || len(_s.Bytes()) > s.blockSize {
		return nil
	}
	return _s
}

func (s *Signature) completion(num *big.Int) []byte {
	expectedLen := s.blockSize
	b := num.Bytes()

	for len(b) < expectedLen {
		b = append([]byte{0}, b...)
	}

	return b
}
