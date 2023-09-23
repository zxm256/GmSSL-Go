package main

import (
	"gmssl.org/gmssl"
	"fmt"
)

func main() {
	version := gmssl.GetVersions()
	fmt.Printf("GmSSL-Go Version: %s\n", version[0])
	fmt.Printf("GmSSL Library Version: %s\n", version[1])

	key, _ := gmssl.RandBytes(16)
	fmt.Printf("RandBytes(32) : %x\n", key)

	fmt.Printf("Sm3DigestSize : %d\n", gmssl.Sm3DigestSize)

	sm3, _ := gmssl.NewSM3Context()
	sm3.Update([]byte("abc"))
	dgst, _ := sm3.Finish()
	fmt.Printf("Sm3('abc') : %x\n", dgst)

	fmt.Printf("Sm3HmacMinKeySize = %d\n", gmssl.Sm3HmacMinKeySize)
	fmt.Printf("Sm3HmacMaxKeySize = %d\n", gmssl.Sm3HmacMaxKeySize)
	fmt.Printf("Sm3HmacSize = %d\n", gmssl.Sm3HmacSize)

	hmac, _ := gmssl.NewSM3HMACContext(key)
	hmac.Update([]byte("abc"))
	mac, _ := hmac.Finish()
	fmt.Printf("Sm3Hmac('abc') : %x\n", mac)

	fmt.Printf("Sm3Pbkdf2MinIter = %d\n", gmssl.Sm3Pbkdf2MinIter)
	fmt.Printf("Sm3Pbkdf2MaxIter = %d\n", gmssl.Sm3Pbkdf2MaxIter)
	fmt.Printf("Sm3Pbkdf2MaxSaltSize = %d\n", gmssl.Sm3Pbkdf2MaxSaltSize)
	fmt.Printf("Sm3Pbkdf2DefaultSaltSize = %d\n", gmssl.Sm3Pbkdf2DefaultSaltSize)
	fmt.Printf("Sm3Pbkdf2MaxKeySize = %d\n", gmssl.Sm3Pbkdf2MaxKeySize)

	salt, _ := gmssl.RandBytes(gmssl.Sm3Pbkdf2DefaultSaltSize)
	kdf_key, _ := gmssl.Sm3Pbkdf2("Password", salt, gmssl.Sm3Pbkdf2MinIter, gmssl.Sm3HmacMinKeySize)
	fmt.Printf("Sm3Pbkdf2('Password') : %x\n", kdf_key)

	fmt.Print("Sm4KeySize = %d\n", gmssl.Sm4KeySize)
	fmt.Print("Sm4BlockSize = %d\n", gmssl.Sm4BlockSize)

	block, _ := gmssl.RandBytes(gmssl.Sm4BlockSize)
	sm4_enc, _ := gmssl.NewSm4(key, true)
	cblock, _ := sm4_enc.Encrypt(block)
	fmt.Printf("SM4 Plaintext : %x\n", block)
	fmt.Printf("SM4 Ciphertext: %x\n", cblock)

	sm4_dec, _ := gmssl.NewSm4(key, false)
	dblock, _ := sm4_dec.Encrypt(cblock)
	fmt.Printf("SM4 Decrypted : %x\n", dblock)




}
