package main

import (
	"fmt"

	kyber "github.com/kudelskisecurity/crystals-go/crystals-kyber"
)

func main() {
	k := kyber.NewKyber512()
	pk, sk := k.PKEKeyGen(nil)
	ciphertext := k.Encrypt(pk, []byte(""), nil)

	fmt.Println("ciphertext:", ciphertext, "\n")

	message := k.Decrypt(sk, ciphertext)

	fmt.Println("plaintext:", message, "\n")
}
