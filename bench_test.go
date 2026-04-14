package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
	"testing"

	"github.com/cloudflare/bn256"
)

func BenchmarkSHA256(b *testing.B) {
	data := make([]byte, 128)
	rand.Read(data)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		h := sha256.New()
		h.Write(data)
		h.Sum(nil)
	}
}

// ------------------------------
// Scalar multiplication on BN256 G1
// ------------------------------
func BenchmarkECCMul(b *testing.B) {
	kBytes := make([]byte, 32)
	rand.Read(kBytes)
	k := new(big.Int).SetBytes(kBytes)
	k.Mod(k, bn256.Order)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		// ECC Mul
		new(bn256.G1).ScalarBaseMult(k)
	}
}

// ------------------------------
// Scalar addition on bn256 G1
// ------------------------------
func BenchmarkECCAdd(b *testing.B) {
	k1, _ := rand.Int(rand.Reader, bn256.Order)
	k2, _ := rand.Int(rand.Reader, bn256.Order)
	P1 := new(bn256.G1).ScalarBaseMult(k1)
	P2 := new(bn256.G1).ScalarBaseMult(k2)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		new(bn256.G1).Add(P1, P2)
	}
}

// ------------------------------
// AES CTR
// ------------------------------
func BenchmarkAESCTREncrypt(b *testing.B) {
	key := make([]byte, 16)
	rand.Read(key)
	plaintext := make([]byte, 128)
	rand.Read(plaintext)
	block, _ := aes.NewCipher(key)
	nonce := make([]byte, aes.BlockSize)
	rand.Read(nonce)
	ciphertext := make([]byte, len(plaintext))

	stream := cipher.NewCTR(block, nonce)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		stream.XORKeyStream(ciphertext, plaintext)
	}
}

func BenchmarkAESCTRDecrypt(b *testing.B) {
	key := make([]byte, 16)
	rand.Read(key)
	plaintext := make([]byte, 128)
	rand.Read(plaintext)
	block, _ := aes.NewCipher(key)
	nonce := make([]byte, aes.BlockSize)
	rand.Read(nonce)
	ciphertext := make([]byte, len(plaintext))

	encStream := cipher.NewCTR(block, nonce)
	encStream.XORKeyStream(ciphertext, plaintext)

	decStream := cipher.NewCTR(block, nonce)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		decStream.XORKeyStream(plaintext, ciphertext)
	}
}

// ------------------------------
// Bilinear Pairing
// ------------------------------
func BenchmarkBilinearPairing(b *testing.B) {
	order := bn256.Order

	aBytes := make([]byte, 32)
	bBytes := make([]byte, 32)
	rand.Read(aBytes)
	rand.Read(bBytes)
	a := new(big.Int).SetBytes(aBytes)
	bInt := new(big.Int).SetBytes(bBytes)
	a.Mod(a, order)
	bInt.Mod(bInt, order)

	P := new(bn256.G1).ScalarBaseMult(a)
	Q := new(bn256.G2).ScalarBaseMult(bInt)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		bn256.Pair(P, Q)
	}
}

// ------------------------------
// Chebyshev (Matrix Fast Exponentiation Optimization)
// ------------------------------
type Matrix [2][2]*big.Int

func matMul(a, b Matrix, mod *big.Int) Matrix {
	var res Matrix
	res[0][0] = new(big.Int).Mul(a[0][0], b[0][0])
	res[0][0].Add(res[0][0], new(big.Int).Mul(a[0][1], b[1][0]))
	res[0][0].Mod(res[0][0], mod)

	res[0][1] = new(big.Int).Mul(a[0][0], b[0][1])
	res[0][1].Add(res[0][1], new(big.Int).Mul(a[0][1], b[1][1]))
	res[0][1].Mod(res[0][1], mod)

	res[1][0] = new(big.Int).Mul(a[1][0], b[0][0])
	res[1][0].Add(res[1][0], new(big.Int).Mul(a[1][1], b[1][0]))
	res[1][0].Mod(res[1][0], mod)

	res[1][1] = new(big.Int).Mul(a[1][0], b[0][1])
	res[1][1].Add(res[1][1], new(big.Int).Mul(a[1][1], b[1][1]))
	res[1][1].Mod(res[1][1], mod)

	return res
}

func matPow(mat Matrix, power, mod *big.Int) Matrix {
	res := Matrix{
		{big.NewInt(1), big.NewInt(0)},
		{big.NewInt(0), big.NewInt(1)},
	}

	zero := big.NewInt(0)
	p := new(big.Int).Set(power)

	for p.Cmp(zero) > 0 {
		if new(big.Int).And(p, big.NewInt(1)).Cmp(big.NewInt(1)) == 0 {
			res = matMul(res, mat, mod)
		}
		mat = matMul(mat, mat, mod)
		p.Rsh(p, 1)
	}
	return res
}

// T_n(x) mod mod
func chebyshevFast(n, x, mod *big.Int) *big.Int {
	zero := big.NewInt(0)
	one := big.NewInt(1)
	two := big.NewInt(2)

	if n.Cmp(zero) == 0 {
		return new(big.Int).Mod(one, mod)
	}
	if n.Cmp(one) == 0 {
		return new(big.Int).Mod(x, mod)
	}

	twoX := new(big.Int).Mul(two, x)
	twoX.Mod(twoX, mod)

	mat := Matrix{
		{big.NewInt(0), big.NewInt(1)},
		{big.NewInt(1), twoX},
	}

	exp := new(big.Int).Sub(n, one)
	matN := matPow(mat, exp, mod)

	t1 := new(big.Int).Mod(x, mod)
	t2 := new(big.Int).Mul(two, x)
	t2.Mul(t2, x)
	t2.Sub(t2, one)
	t2.Mod(t2, mod)

	res := new(big.Int).Mul(matN[0][0], t1)
	res.Add(res, new(big.Int).Mul(matN[0][1], t2))
	res.Mod(res, mod)

	return res
}

func BenchmarkChebyshev160(b *testing.B) {
	mod, _ := new(big.Int).SetString("1120333675872070021299531270329543505825074287223", 10)
	x := big.NewInt(25749480)

	sBytes := make([]byte, 20) // 160 bit
	rand.Read(sBytes)
	s := new(big.Int).SetBytes(sBytes)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		chebyshevFast(s, x, mod)
	}
}
