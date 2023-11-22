package ellipticcurve

import "math/big"

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

	for i := k.BitLen() - 1; i >= 0; i-- {
		if k.Bit(i) == 1 {
			res = c.Sum(res, p)
		} else {
			res = c.Sum(res, res)
		}
	}

	return res
}

func (c *Curve) Sum(a, b Point) Point {
	if b.IsNull() {
		return a
	} else if a.IsNull() {
		return b
	}

	x := big.NewInt(0)
	y := big.NewInt(0)

	if b.Equal(a) {
		// lambda = ((a.X**2 * 3 + a) * a.Y * 2).ModInverse
		lambda := new(big.Int).Exp(a.X, big.NewInt(2), nil)               // lambda = a.X**2
		lambda = lambda.Mul(lambda, big.NewInt(3))                        // lambda *= 3
		lambda = lambda.Add(lambda, c.a)                                  // lambda += a
		lambda = lambda.Mul(lambda, new(big.Int).Mul(a.Y, big.NewInt(2))) // lambda *= a.Y * 2
		lambda = lambda.ModInverse(lambda, c.p)                           // lambda.ModInverse

		// x = (lambda**2 - a.X * 2) % p
		x = x.Exp(lambda, big.NewInt(2), nil)              // x = lambda**2
		x = x.Sub(x, new(big.Int).Mul(a.X, big.NewInt(2))) // x -= a.X * 2
		x = x.Mod(x, c.p)                                  // x %= p

		// y = (-a.Y + lambda * (a.X - x)) % p
		y = y.Neg(a.Y)                                                   // y = -a.Y
		y = y.Add(y, new(big.Int).Mul(lambda, new(big.Int).Sub(a.X, x))) // y += lambda * (a.X - x)
		y = y.Mod(y, c.p)                                                // y %= p
	} else {
		// lambda = ((b.Y - a.Y) * (b.X - a.X)) % p
		lambda := new(big.Int).Sub(b.Y, a.Y)                    // lambda = b.Y - a.Y
		lambda = lambda.Mul(lambda, new(big.Int).Sub(b.X, a.X)) // lambda *= b.X - a.X
		lambda = lambda.ModInverse(lambda, c.p)                 // lambda %= p

		// x = ((lambda**2 mod |2|) - b.X - a.X) % p
		x = new(big.Int).Exp(lambda, big.NewInt(2), c.p) // x = lambda**2 mod |2|
		x = x.Sub(x, b.X)                                // x -= b.X
		x = x.Sub(x, a.X)                                // x -= a.X
		x = x.Mod(x, c.p)                                // x %= p

		// y = ((-a.Y % p) + lambda * (a.X - x)) % p
		y = y.Neg(a.Y)                                                   // y = -a.Y
		y = y.Mod(y, c.p)                                                // y %= p
		y = y.Add(y, new(big.Int).Mul(lambda, new(big.Int).Sub(a.X, x))) // y += lambda * (a.X -  x)
		y = y.Mod(y, c.p)                                                // y %= p
	}

	return Point{x, y}
}
