package ellipticcurve

import "math/big"

var zero = big.NewInt(0)

type Point struct {
	X, Y *big.Int
}

func (p Point) Equal(b Point) bool {
	return p.X.Cmp(b.X) == 0 && p.Y.Cmp(b.Y) == 0
}

func (p Point) IsNull() bool {
	return p.X.Cmp(big.NewInt(0)) == 0 && p.Y.Cmp(big.NewInt(0)) == 0
}

type Curve struct {
	p, a *big.Int
}

func NewCurve(p, a *big.Int) *Curve {
	return &Curve{p, a}
}

func (c *Curve) Scalar(k *big.Int, p Point) Point {
	res := Point{big.NewInt(0), big.NewInt(0)}

	for i := k.BitLen(); i >= 0; i-- {
		res = c.Double(res)
		if k.Bit(i) == 1 {
			res = c.Sum(res, p)
		}
	}

	return res
}

func (c *Curve) Double(a Point) Point {
	if a.IsNull() {
		return a
	}

	x := big.NewInt(0)
	y := big.NewInt(0)

	dx := new(big.Int).Add(a.Y, a.Y)

	if dx.Cmp(zero) < 0 {
		dx = dx.Add(dx, c.p)
	}

	dy := new(big.Int).Mul(a.X, a.X)
	dy = dy.Mul(dy, big.NewInt(3))
	dy = dy.Add(dy, c.a)

	if dy.Cmp(zero) < 0 {
		dy = dy.Add(dy, c.p)
	}

	m := dx.ModInverse(dx, c.p)
	m = m.Mul(m, dy)
	m = m.Mod(m, c.p)

	x = x.Mul(m, m)
	x = x.Sub(x, a.X)
	x = x.Sub(x, a.X)
	x = x.Mod(x, c.p)

	if x.Cmp(zero) < 0 {
		x = x.Add(x, c.p)
	}

	y = y.Sub(a.X, x)
	y = y.Mul(y, m)
	y = y.Sub(y, a.Y)
	y = y.Mod(y, c.p)

	if y.Cmp(zero) < 0 {
		y = y.Add(y, c.p)
	}

	return Point{x, y}
}

func (c *Curve) Sum(a, b Point) Point {
	if b.IsNull() {
		return a
	} else if a.IsNull() {
		return b
	}

	x := big.NewInt(0)
	y := big.NewInt(0)

	dx := new(big.Int).Sub(b.X, a.X)

	if dx.Cmp(zero) < 0 {
		dx = dx.Add(dx, c.p)
	}

	dy := new(big.Int).Sub(b.Y, a.Y)

	if dy.Cmp(zero) < 0 {
		dy = dy.Add(dy, c.p)
	}

	m := dx.ModInverse(dx, c.p)
	m = m.Mul(m, dy)
	m = m.Mod(m, c.p)

	if m.Cmp(zero) < 0 {
		m = m.Add(m, c.p)
	}

	x = x.Mul(m, m)
	x = x.Sub(x, a.X)
	x = x.Sub(x, b.X)
	x = x.Mod(x, c.p)

	if x.Cmp(zero) < 0 {
		x = x.Add(x, c.p)
	}

	y = y.Sub(a.X, x)
	y = y.Mul(y, m)
	y = y.Sub(y, a.Y)
	y = y.Mod(y, c.p)

	if y.Cmp(zero) < 0 {
		y = y.Add(y, c.p)
	}

	return Point{x, y}
}
