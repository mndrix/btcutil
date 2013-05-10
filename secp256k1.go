package btcutil

import "crypto/elliptic"
import "fmt"
import "math/big"

// secp256k1 curve parameters.  Only available after init() has completed
var Secp256k1 *elliptic.CurveParams

func init() {
	var p, n, gx, gy big.Int
	fmt.Sscan("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", &p)
	fmt.Sscan("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", &n)
	fmt.Sscan("0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", &gx)
	fmt.Sscan("0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", &gy)
	b := big.NewInt(7)
	Secp256k1 = &elliptic.CurveParams{
		P:       &p,
		N:       &n,
		B:       b,
		Gx:      &gx,
		Gy:      &gy,
		BitSize: 256,
	}
}
