package main

import (
	"hash"
	"math"
	"math/big"

	curve "github.com/dece2183/go-digisig/ellipticCurve"
)

type Validator struct {
	// external parameters
	p, a, q  *big.Int
	_P, _Q   curve.Point
	hashFunc hash.Hash
	// internal variables
	curve *curve.Curve
}

func NewValidator(pubKey curve.Point, p, a, q *big.Int, P curve.Point, hashFunc hash.Hash) *Validator {
	v := &Validator{
		p:        p,
		a:        a,
		q:        q,
		_P:       P,
		_Q:       pubKey,
		hashFunc: hashFunc,
		curve:    curve.NewCurve(p, a),
	}
	return v
}

func (v *Validator) Validate(msg []byte, signature []byte) bool {
	r, s := v.extract(signature)

	if r.Cmp(big.NewInt(0)) <= 0 || r.Cmp(v.q) >= 0 ||
		s.Cmp(big.NewInt(0)) <= 0 || s.Cmp(v.q) >= 0 {
		return false
	}

	v.hashFunc.Reset()
	v.hashFunc.Write(msg)

	hs := big.NewInt(0).SetBytes(v.hashFunc.Sum([]byte{}))
	e := v.calcE(hs)

	C := v.calcC(e, s, r).X
	R := C.Mod(C, v.q)

	return R.Cmp(r) == 0
}

func (v *Validator) extract(signature []byte) (r, s *big.Int) {
	offset := int(math.Ceil(float64(v.p.BitLen()) / 8))
	r = new(big.Int).SetBytes(signature[0:offset])
	s = new(big.Int).SetBytes(signature[offset:])
	return
}

func (v *Validator) calcE(hs *big.Int) *big.Int {
	e := hs.Mod(hs, v.q)
	if e.Cmp(big.NewInt(0)) == 0 {
		return big.NewInt(0)
	}
	return e
}

func (v *Validator) calcC(e, s, r *big.Int) curve.Point {
	_v := e.ModInverse(e, v.q)
	// z1 = (s * _v) % v.q
	z1 := new(big.Int).Mul(s, _v)
	z1 = z1.Mod(z1, v.q)
	// z2 = (-1 * (r * _v)) % v.q;
	z2 := new(big.Int).Mul(r, _v)
	z2 = z2.Neg(z2)
	z2 = z2.Mod(z2, v.q)

	return v.curve.Sum(v.curve.Scalar(z1, v._P), v.curve.Scalar(z2, v._Q))
}
