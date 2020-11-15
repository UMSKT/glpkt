package main

import (
    "crypto/rand"
    "errors"
    "math/big"
)

type Point struct {
    X *big.Int
    Y *big.Int
    Z *big.Int
}

type Curve struct {
    P *big.Int
    A *big.Int
    B *big.Int
}

var ZERO *big.Int = big.NewInt(0)
var ONE *big.Int = big.NewInt(1)

func (P *Point) IsAtInfinity() bool {
    return (P.X.Cmp(ZERO) == 0 &&
    P.Y.Cmp(ONE) == 0 &&
    P.Z.Cmp(ZERO) == 0)
}

// We need to do this ourselves because stdlib crypto/elliptic only has support for a = -3, but we need to support a = 1
func (curve *Curve) AddPoints(P, Q Point) (R Point) {
    R.X = new(big.Int)
    R.Y = new(big.Int)
    R.Z = new(big.Int)

    if P.IsAtInfinity() {
        R.X.Set(Q.X)
        R.Y.Set(Q.Y)
        R.Z.Set(Q.Z)
        return R
    } else if Q.IsAtInfinity() {
        R.X.Set(P.X)
        R.Y.Set(P.Y)
        R.Z.Set(P.Z)
        return R
    }

    X1, Y1, Z1 := P.X, P.Y, P.Z
    X2, Y2, Z2 := Q.X, Q.Y, Q.Z

    U1 := new(big.Int).Mul(Z2, Z2)
    U1.Mul(U1, X1).Mod(U1, curve.P)

    U2 := new(big.Int).Mul(Z1, Z1)
    U2.Mul(U2, X2).Mod(U2, curve.P)

    S1 := new(big.Int).Mul(Z2, Z2)
    S1.Mul(S1, Z2).Mul(S1, Y1).Mod(S1, curve.P)

    S2 := new(big.Int).Mul(Z1, Z1)
    S2.Mul(S2, Z1).Mul(S2, Y2).Mod(S2, curve.P)

    if U1.Cmp(U2) == 0 {
        if S1.Cmp(S2) != 0 {
            R.X.SetInt64(0)
            R.Y.SetInt64(1)
            R.Z.SetInt64(0)
            return R
        }
        // point doubling
        if Y1.Cmp(ZERO) == 0 {
            R.X.SetInt64(0)
            R.Y.SetInt64(1)
            R.Z.SetInt64(0)
            return R
        }
        // S = 4*X*Y²
        S := new(big.Int).Set(X1)
        S.Mul(S, Y1).Mul(S, Y1).Lsh(S, 2)
        S.Mod(S, curve.P)
        // M = 3*X² + a*Z⁴
        M := big.NewInt(3)
        M.Mul(M, X1).Mul(M, X1)
        aZ4 := new(big.Int).Set(Z1)
        aZ4.Mul(aZ4, aZ4).Mul(aZ4, aZ4)
        aZ4.Mul(aZ4, curve.A)
        aZ4.Mod(aZ4, curve.P)
        M.Add(M, aZ4).Mod(M, curve.P)
        // X' = M² - 2S
        R.X.Lsh(S, 1)
        R.X.Sub(new(big.Int).Mul(M, M), R.X)
        R.X.Mod(R.X, curve.P)
        // Y' = M*(S - X') - 8*Y⁴
        R.Y.Sub(S, R.X).Mul(R.Y, M)
        EightY4 := new(big.Int).Set(Y1)
        EightY4.Mul(EightY4, EightY4).Mul(EightY4, EightY4)
        EightY4.Lsh(EightY4, 3)
        R.Y.Sub(R.Y, EightY4)
        R.Y.Mod(R.Y, curve.P)
        // Z' = 2*Y*Z
        R.Z.Mul(Z1, Y1).Lsh(R.Z, 1)
        R.Z.Mod(R.Z, curve.P)
        return R
    } else {
        // point addition
        H := new(big.Int).Sub(U2, U1)
        H.Mod(H, curve.P)
        Rr := new(big.Int).Sub(S2, S1)
        Rr.Mod(Rr, curve.P)
        // X3 = R² - H³ - 2*U1*H²
        R2 := new(big.Int).Mul(Rr, Rr)
        H2 := new(big.Int).Mul(H, H)
        U1H2 := new(big.Int).Mul(U1, H2)
        H3 := new(big.Int).Mul(H2, H)
        TwoU1H2 := new(big.Int).Set(U1H2)
        TwoU1H2.Lsh(TwoU1H2, 1)
        R.X.Sub(R2, H3)
        R.X.Sub(R.X, TwoU1H2)
        R.X.Mod(R.X, curve.P)
        // Y3 = R*(U1*H² - X3) - S1*H³
        S1H3 := new(big.Int).Mul(S1, H3)
        R.Y.Sub(U1H2, R.X).Mul(R.Y, Rr).Sub(R.Y, S1H3)
        R.Y.Mod(R.Y, curve.P)
        // Z3 = H*Z1*Z2
        R.Z.Mul(Z2, Z1).Mul(R.Z, H)
        R.Z.Mod(R.Z, curve.P)
        return R
    }
}

func (curve *Curve) ScalarMult(k *big.Int, P Point) (Point) {
    Q := Point{new(big.Int).Set(P.X), new(big.Int).Set(P.Y), new(big.Int).Set(P.Z)}
    R := Point{big.NewInt(0), big.NewInt(1), big.NewInt(0)}
    e := new(big.Int).Set(k)
    for ; e.Cmp(ZERO) != 0; e.Rsh(e, 1) {
        if e.Bit(0) == 1 {
            R = curve.AddPoints(R, Q)
        }
        Q = curve.AddPoints(Q, Q)
    }

    return R
}

func (curve *Curve) Affinize(P *Point) (*Point) {
    if P.IsAtInfinity() { // would otherwise cause div by zero
        return P
    }

    iz := new(big.Int).ModInverse(P.Z, curve.P)
    iz2 := new(big.Int).Mul(iz, iz)
    P.X.Mul(P.X, iz2).Mod(P.X, curve.P)
    iz.Mul(iz, iz2)
    P.Y.Mul(P.Y, iz).Mod(P.Y, curve.P)
    P.Z.SetInt64(1)

    return P
}

func ceildiv(a, b int) int {
    return (a + b - 1) / b
}

func generateBINK(binkId uint32) (bink BINK, err error) {
    // This uses the sizes used for Windows Server 2003. For XP, set lq = 56, lp = 384, hashbits = 28
    // \item Fix $\ell _q$. This must actually be one bigger than the result because of how the scalar derivation works for 20020420 product key validation (bitcpycap32 for lq bits may otherwise yield a number that exceeds lq).
    lq := 63
    // \item Fix $\ell _p$ such that $\ell _p > \ell _q$.
    lp := 512
    // hashbits := 31
    var q *big.Int
    var a, b, c, d *big.Int
    for {
        // \item Choose a random $\frac{\ell _q+1}{2}$-bit integer $a$ and make it odd.
        var abBitLen int
        if lq % 2 == 0 {
            abBitLen = ceildiv(lq + 1, 2)
        } else {
            abBitLen = ceildiv(lq - 1, 2)
        }
        abMax := big.NewInt(1)
        abMax.Lsh(abMax, uint(abBitLen + 1)).Sub(abMax, ONE)
        for {
            a, err = rand.Int(rand.Reader, abMax)
            if err != nil {
                return bink, err
            }
            if a.BitLen() == abBitLen {
                break
            }
            vPrintf("bad a len (%d != %d with max %x)\n", a.BitLen(), abBitLen, abMax)
        }
        a.SetBit(a, 0, 1)
        // \item Choose a random $\frac{\ell _q+1}{2}$-bit integer $b$ and make it even.
        for {
            b, err = rand.Int(rand.Reader, abMax)
            if err != nil {
                return bink, err
            }
            if b.BitLen() == abBitLen {
                break
            }
            vPrintf("bad b len (%d != %d with max %x)\n", b.BitLen(), abBitLen, abMax)
        }
        b.SetBit(b, 0, 0)
        // \item Set $q=a^2 + b^2$.
        q = new(big.Int).Add(new(big.Int).Mul(a, a), new(big.Int).Mul(b, b))
        // \item If the bit length of $q$ is not $\ell _q$, return to step~3.
        if q.BitLen() == lq {
            // \item If $q$ is not prime, return to step~3.
            // M-R test iterations taken from FIPS 186-4 section C.3 table C.1; we're significantly below p and q values for normal DSA though
            if q.ProbablyPrime(40) {
                break
            }
            vPrintf("q not prime\n")
        }
        vPrintf("bad q len (%d != %d)\n", q.BitLen(), lq)
    }
    vPrintf("q = %d\n", q)

    var p *big.Int
    var n *big.Int // order of the curve
    for {
        // \item Choose a random $(\frac{\ell _p - \ell _q}{2}+1$)-bit integer $c$ and make it a multiple of four, e.g. by clearing the bottom two~bits.
        cdBitLen := ((lp - lq) + 2 - 1) / 2
        cdMax := big.NewInt(1)
        cdMax.Lsh(cdMax, uint(cdBitLen))
        for {
            c, err = rand.Int(rand.Reader, cdMax)
            if err != nil {
                return bink, err
            }
            if c.BitLen() == cdBitLen {
                break
            }
        }
        c.SetBit(c, 0, 0)
        c.SetBit(c, 1, 0)
        // \item Choose a random $(\frac{\ell _p - \ell _q}{2}+1)$-bit integer $d$ and make it a multiple of four.

        for {
            d, err = rand.Int(rand.Reader, cdMax)
            if err != nil {
                return bink, err
            }
            if d.BitLen() == cdBitLen {
                break
            }
        }
        d.SetBit(d, 0, 0)
        d.SetBit(d, 1, 0)

        // \item $\alpha=ac+bd+1$
        ac := new(big.Int).Mul(a, c)
        bd := new(big.Int).Mul(b, d)
        alpha := new(big.Int).Add(ac, bd)
        alpha.Add(alpha, big.NewInt(1))

        // \item $\beta=|ad-bc|$
        ad := new(big.Int).Mul(a, d)
        bc := new(big.Int).Mul(b, c)
        beta := new(big.Int).Sub(ad, bc)
        beta = beta.Abs(beta)

        // \item $p=\alpha^2+\beta^2$
        p = new(big.Int).Add(new(big.Int).Mul(alpha, alpha), new(big.Int).Mul(beta, beta))

        // \item If the bit length of $p$ is not $\ell _p$, return to step~8.
        if p.BitLen() == lp {
            // \item If $p$ is not prime, return to step~8.
            if p.ProbablyPrime(40) {
                n = new(big.Int).Add(p, big.NewInt(1))
                n.Sub(n, new(big.Int).Mul(big.NewInt(2), alpha))
                break
            }
        }
    }

    //  E(GF(p)): y^2 = x^3 + x [curve params a = 1, b = 0]
    // #E(GF(p)): n = p + 1 - 2\alpha
    vPrintf("Curve E defined by y^2 = x^3 + x over GF(%d)\n", p)
    vPrintf("#E = %d\n", n)

    // We now have the order of the curve and the prime order q of a base point B.
    // First find a generator point G of order n, which is any point for which [n]G == 0.
    var curve *Curve = &Curve{p, big.NewInt(1), new(big.Int)}

    var G Point
    for {
        // To find a random point, first try random x-coordinates < p and see if it is a square residues modulo p. If so, then (x_cand, sqrt(y_cand)) is a valid point.
        x, err := rand.Int(rand.Reader, p)
        if err != nil {
            return bink, err
        }
        yy := new(big.Int).Mul(x, x)
        yy.Mul(yy, x)
        yy.Add(yy, x)
        y := yy.ModSqrt(yy, p)
        if y == nil {
            continue
        }
        // Given a valid point (x, y), try scalar multiplication with n. If the result is the point at infinity, we know it's a generator.

        G.X = x
        G.Y = y
        G.Z = big.NewInt(1)

        nG := curve.ScalarMult(n, G)
        if nG.IsAtInfinity() {
            break
        }
    }

    // The point B will be a generator point of the subgroup of the group generated by G. Because the order of a subgroup always evenly divides the order of the entire group, we can compute n/q and multiply G by that, leaving us with a point of order q.
    h := new(big.Int).Div(n, q)
    B := curve.ScalarMult(h, G)
    curve.Affinize(&B)

    X := curve.ScalarMult(q, B)
    if !X.IsAtInfinity() {
        return bink, errors.New("order of B is not q")
    }

    // Now pick a random scalar k such that 0 < k < q, get K = [k]B and output key pair (k, K).
    k, err := rand.Int(rand.Reader, q)
    if err != nil {
        return bink, err
    }

    K := curve.ScalarMult(k, B)
    curve.Affinize(&K)

    bink.BasePointOrder = q
    bink.SecretKey = k

    bink.ResourceId = binkId
    bink.Version = 20020420
    bink.CurveParamWords = uint32(p.BitLen() / 32)

    if bink.Version == 20020420 {
        bink.OffsetToCurveParams = 9
        bink.PKHashBits = 31
        bink.PKScalarBits = uint32(lq - 1) // Take care when *generating* keys that ceil(log2(y)) <= PKScalarBits because q > PKScalarBits.
        bink.AuthValueBits = 10
        bink.PIDBits = 20
    } else {
        bink.OffsetToCurveParams = 7
        bink.PKHashBits = 28
        bink.PKScalarBits = uint32(lq - 1)
    }
    bink.Size = 4 * bink.OffsetToCurveParams + 7 * 4 * bink.CurveParamWords

    // Checksum is only generated and written on serialization

    bink.Curve = *curve
    bink.B = B
    bink.K = K

    return bink, nil
}

