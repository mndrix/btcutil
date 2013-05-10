package main

import "crypto/ecdsa"
import "crypto/rand"
import "fmt"
import "math/big"
import "github.com/mndrix/btcutil"

type Signature struct {
    m, s    *big.Int
    F       *ecdsa.PublicKey
}

// Based on algorithm described in An Efficient Blind Signature Scheme
// Based on the Elliptic Curve Discrete Logarithm Problem by
// Nikooghadam and Zakerolhosseini
func main() {
    crv := btcutil.Secp256k1

	// generate keys for Signer
	signer, _ := btcutil.GenerateKey(rand.Reader)
    d := signer.D
    Q := signer.PublicKey
	fmt.Printf("Signer:\t%x\n\t%x\n", d, Q.X)
	fmt.Println("")

    // generate k and R for each user request (§4.2)
	request, err := btcutil.GenerateKey(rand.Reader)
    maybePanic(err)
    k := request.D
    R := request.PublicKey

    // generate F which is not equal to O (§4.2)
    var a, b, c, bInv *big.Int
    F := new(ecdsa.PublicKey)
    for F.X==nil && F.Y==nil {
        // requester's three blinding factors (§4.2)
        a, err = btcutil.RandFieldElement(rand.Reader)
        maybePanic(err)
        b, err = btcutil.RandFieldElement(rand.Reader)
        maybePanic(err)
        c, err = btcutil.RandFieldElement(rand.Reader)
        maybePanic(err)

        // requester calculates point F (§4.2)
        bInv = new(big.Int).ModInverse(b, crv.N)
        abInv := new(big.Int).Mul(a, bInv)
        abInv.Mod(abInv, crv.N)
        bInvR := btcutil.ScalarMult(bInv, &R)
        abInvQ := btcutil.ScalarMult(abInv, &Q)
        cG := btcutil.ScalarBaseMult(c)
        F = btcutil.Add(bInvR, abInvQ)
        F = btcutil.Add(F, cG)
    }

    // names per §4.2
    x0 := F.X

    // message which the requester want's signed
    m, err := btcutil.RandFieldElement(rand.Reader)

    // calculate r and m̂
    r := new(big.Int).Mod(x0, crv.N)
    mHat := new(big.Int).Mul(new(big.Int).Mul(b,r),m)
    mHat.Add(mHat,a)
    mHat.Mod(mHat, crv.N)

    // signer generates signature (§4.3)
    sHat := new(big.Int).Mul(d,mHat)
    sHat.Add(sHat,k)
    sHat.Mod(sHat, crv.N)

    // requester extracts the real signature (§4.4)
    s := new(big.Int).Mul(bInv, sHat)
    s.Add(s, c)
    s.Mod(s, crv.N)
    sig := &Signature{m,s,F}
    fmt.Printf("sig = %s\n\n", sig)

    // onlooker verifies signature (§4.5)
    sG := btcutil.ScalarBaseMult(sig.s)
    rm := new(big.Int).Mul(new(big.Int).Mod(sig.F.X,crv.N), sig.m)
    rm.Mod(rm, crv.N)
    rmQ := btcutil.ScalarMult(rm, &Q)
    rmQplusF := btcutil.Add(rmQ, sig.F)

    fmt.Printf("%s\n%s\n", sG, rmQplusF)
    if btcutil.KeysEqual(sG, rmQplusF) {
        fmt.Printf("valid signature\n")
    }
}

func maybePanic(err error) {
    if err != nil {
        panic(err)
    }
}
