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

	fmt.Printf("Sm4KeySize = %d\n", gmssl.Sm4KeySize)
	fmt.Printf("Sm4BlockSize = %d\n", gmssl.Sm4BlockSize)

	block, _ := gmssl.RandBytes(gmssl.Sm4BlockSize)
	sm4_enc, _ := gmssl.NewSm4(key, true)
	cblock, _ := sm4_enc.Encrypt(block)
	fmt.Printf("SM4 Plaintext : %x\n", block)
	fmt.Printf("SM4 Ciphertext: %x\n", cblock)

	sm4_dec, _ := gmssl.NewSm4(key, false)
	dblock, _ := sm4_dec.Encrypt(cblock)
	fmt.Printf("SM4 Decrypted : %x\n", dblock)

	fmt.Printf("Sm4CbcIvSize = %d\n", gmssl.Sm4CbcIvSize)
	iv, _ := gmssl.RandBytes(gmssl.Sm4CbcIvSize)

	sm4_cbc_enc, _ := gmssl.NewSM4CBCContext(key, iv, true)
	cbc_ciphertext, _ := sm4_cbc_enc.Update([]byte("abc"))
	cbc_ciphertext_last, _ := sm4_cbc_enc.Finish()
	cbc_ciphertext = append(cbc_ciphertext, cbc_ciphertext_last...)
	fmt.Printf("ciphertext = %x\n", cbc_ciphertext)
	sm4_cbc_dec, _ := gmssl.NewSM4CBCContext(key, iv, false)
	cbc_plaintext, _ := sm4_cbc_dec.Update(cbc_ciphertext)
	cbc_plaintext_last, _ := sm4_cbc_dec.Finish()
	cbc_plaintext = append(cbc_plaintext, cbc_plaintext_last...)
	fmt.Printf("plaintext = %x\n", cbc_plaintext)

	sm4_ctr, _ := gmssl.NewSM4CTRContext(key, iv)
	ctr_ciphertext, _ := sm4_ctr.Update([]byte("abc"))
	ctr_ciphertext_last, _ := sm4_ctr.Finish()
	ctr_ciphertext = append(ctr_ciphertext, ctr_ciphertext_last...)
	fmt.Printf("ciphertext = %x\n", ctr_ciphertext)

	sm4_ctr, _ = gmssl.NewSM4CTRContext(key, iv)
	ctr_plaintext, _ := sm4_ctr.Update(ctr_ciphertext)
	ctr_plaintext_last, _ := sm4_ctr.Finish()
	ctr_plaintext = append(ctr_plaintext, ctr_plaintext_last...)
	fmt.Printf("plaintext = %x\n", ctr_plaintext)


	fmt.Printf("Sm4GcmMinIvSize = %d\n", gmssl.Sm4GcmMinIvSize)
	fmt.Printf("Sm4GcmMinIvSize = %d\n", gmssl.Sm4GcmMinIvSize)
	fmt.Printf("Sm4GcmDefaultIvSize = %d\n", gmssl.Sm4GcmDefaultIvSize)
	fmt.Printf("Sm4GcmDefaultTagSize = %d\n", gmssl.Sm4GcmDefaultTagSize)
	fmt.Printf("Sm4GcmMaxTagSize = %d\n", gmssl.Sm4GcmMaxTagSize)
	aad, _ := gmssl.RandBytes(20)
	taglen := gmssl.Sm4GcmDefaultTagSize
	iv, _ = gmssl.RandBytes(gmssl.Sm4GcmDefaultIvSize)

	sm4_gcm_enc, _ := gmssl.NewSM4GCMContext(key, iv, aad, taglen, true)
	gcm_ciphertext, _ := sm4_gcm_enc.Update([]byte("abc"))
	gcm_ciphertext_last, _ := sm4_gcm_enc.Finish()
	gcm_ciphertext = append(gcm_ciphertext, gcm_ciphertext_last...)
	fmt.Printf("ciphertext = %x\n", gcm_ciphertext)
	sm4_gcm_dec, _ := gmssl.NewSM4GCMContext(key, iv, aad, taglen, false)
	gcm_plaintext, _ := sm4_gcm_dec.Update(gcm_ciphertext)
	gcm_plaintext_last, _ := sm4_gcm_dec.Finish()
	gcm_plaintext = append(gcm_plaintext, gcm_plaintext_last...)
	fmt.Printf("plaintext = %x\n", gcm_plaintext)


	fmt.Printf("ZucKeySize = %d\n", gmssl.ZucKeySize)
	fmt.Printf("ZucIvSize = %d\n", gmssl.ZucIvSize)
	iv, _ = gmssl.RandBytes(gmssl.ZucIvSize)

	zuc, _ := gmssl.NewZuc(key, iv)
	zuc_ciphertext, _ := zuc.Update([]byte("abc"))
	zuc_ciphertext_last, _ := zuc.Finish()
	zuc_ciphertext = append(zuc_ciphertext, zuc_ciphertext_last...)
	zuc, _ = gmssl.NewZuc(key, iv)
	zuc_plaintext, _ := zuc.Update(zuc_ciphertext)
	zuc_plaintext_last, _ := zuc.Finish()
	zuc_plaintext = append(zuc_plaintext, zuc_plaintext_last...)
	fmt.Printf("plaintext = %x\n", zuc_plaintext)
}
