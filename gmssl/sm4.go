/*
 *  Copyright 2014-2023 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */
/* +build cgo */
package gmssl

/*
#include <stdlib.h>
#include <string.h>
#include <gmssl/sm4.h>
#include <gmssl/mem.h>
#include <gmssl/aead.h>
#include <gmssl/error.h>

SM4_KEY *sm4_key_new(void) {
	SM4_KEY *sm4_key;
	if (!(sm4_key = (SM4_KEY *)malloc(sizeof(SM4_KEY)))) {
		error_print();
		return NULL;
	}
	return sm4_key;
}

void sm4_key_free(SM4_KEY *sm4_key) {
	if (sm4_key) {
		gmssl_secure_clear(sm4_key, sizeof(SM4_KEY));
		free(sm4_key);
	}
}

SM4_CBC_CTX *sm4_cbc_ctx_new(void) {
	SM4_CBC_CTX *sm4_cbc_ctx;
	if (!(sm4_cbc_ctx = (SM4_CBC_CTX *)malloc(sizeof(SM4_CBC_CTX)))) {
		error_print();
		return NULL;
	}
	return sm4_cbc_ctx;
}

void sm4_cbc_ctx_free(SM4_CBC_CTX *sm4_cbc_ctx) {
	if (sm4_cbc_ctx) {
		gmssl_secure_clear(sm4_cbc_ctx, sizeof(SM4_CBC_CTX));
		free(sm4_cbc_ctx);
	}
}

SM4_CTR_CTX *sm4_ctr_ctx_new(void) {
	SM4_CTR_CTX *sm4_ctr_ctx;
	if (!(sm4_ctr_ctx = (SM4_CTR_CTX *)malloc(sizeof(SM4_CTR_CTX)))) {
		error_print();
		return NULL;
	}
	return sm4_ctr_ctx;
}

void sm4_ctr_ctx_free(SM4_CTR_CTX *sm4_ctr_ctx) {
	if (sm4_ctr_ctx) {
		gmssl_secure_clear(sm4_ctr_ctx, sizeof(SM4_CTR_CTX));
		free(sm4_ctr_ctx);
	}
}

SM4_GCM_CTX *sm4_gcm_ctx_new(void) {
	SM4_GCM_CTX *sm4_gcm_ctx;
	if (!(sm4_gcm_ctx = (SM4_GCM_CTX *)malloc(sizeof(SM4_GCM_CTX)))) {
		error_print();
		return NULL;
	}
	return sm4_gcm_ctx;
}

void sm4_gcm_ctx_free(SM4_GCM_CTX *sm4_gcm_ctx) {
	if (sm4_gcm_ctx) {
		gmssl_secure_clear(sm4_gcm_ctx, sizeof(SM4_GCM_CTX));
		free(sm4_gcm_ctx);
	}
}
*/
import "C"

import (
	"errors"
	"runtime"
	"unsafe"
)

const Sm4KeySize = 16
const Sm4BlockSize = 16

type Sm4 struct {
	sm4_key *C.SM4_KEY
	encrypt bool
}

func NewSm4(key []byte, encrypt bool) (*Sm4, error) {
	if key == nil {
		return nil, errors.New("No key")
	}
	if len(key) != int(C.SM4_KEY_SIZE) {
		return nil, errors.New("Invalid key length")
	}
	sm4_key := C.malloc(C.sizeof_SM4_KEY)
	if sm4_key == nil {
		return nil, errors.New("Malloc failure")
	}
	ret := &Sm4{(*C.SM4_KEY)(unsafe.Pointer(sm4_key)), encrypt}
	runtime.SetFinalizer(ret, func(ret *Sm4) {
		C.free(unsafe.Pointer(ret.sm4_key))
	})
	ret.encrypt = encrypt
	if encrypt == true {
		C.sm4_set_encrypt_key((*C.SM4_KEY)(unsafe.Pointer(sm4_key)), (*C.uchar)(&key[0]))
	} else {
		C.sm4_set_decrypt_key((*C.SM4_KEY)(unsafe.Pointer(sm4_key)), (*C.uchar)(&key[0]))
	}
	return ret, nil
}

func (sm4 *Sm4) Encrypt(in []byte) ([]byte, error) {
	if len(in) != int(C.SM4_BLOCK_SIZE) {
		return nil, errors.New("Invalid block size")
	}
	outbuf := make([]byte, C.SM4_BLOCK_SIZE)
	C.sm4_encrypt((*C.SM4_KEY)(unsafe.Pointer(sm4.sm4_key)), (*C.uchar)(&in[0]), (*C.uchar)(unsafe.Pointer(&outbuf[0])))
	return outbuf, nil
}

const Sm4CbcIvSize = 16

type SM4CBCContext struct {
	sm4_cbc_ctx *C.SM4_CBC_CTX
	encrypt bool
}

func NewSM4CBCContext(key []byte, iv []byte, encrypt bool) (*SM4CBCContext, error) {
	if key == nil {
		return nil, errors.New("No key")
	}
	if len(key) != int(C.SM4_KEY_SIZE) {
		return nil, errors.New("Invalid key length")
	}
	if len(iv) != int(C.SM4_BLOCK_SIZE) {
		return nil, errors.New("Invalid IV length")
	}
	sm4_cbc_ctx := C.sm4_cbc_ctx_new()
	if sm4_cbc_ctx == nil {
		return nil, errors.New("Malloc failure")
	}
	ret := &SM4CBCContext{sm4_cbc_ctx, encrypt}
	runtime.SetFinalizer(ret, func(ret *SM4CBCContext) {
		C.sm4_cbc_ctx_free(ret.sm4_cbc_ctx)
	})
	ret.encrypt = encrypt
	if encrypt == true {
		if 1 != C.sm4_cbc_encrypt_init(sm4_cbc_ctx, (*C.uchar)(&key[0]), (*C.uchar)(&iv[0])) {
			return nil, errors.New("Libgmssl inner error")
		}
	} else {
		if 1 != C.sm4_cbc_decrypt_init(sm4_cbc_ctx, (*C.uchar)(&key[0]), (*C.uchar)(&iv[0])) {
			return nil, errors.New("Libgmssl inner error")
		}
	}
	return ret, nil
}

func (ctx *SM4CBCContext) Update(in []byte) ([]byte, error) {
	outbuf := make([]byte, len(in) + C.SM4_BLOCK_SIZE)
	var outlen C.size_t
	if ctx.encrypt {
		if 1 != C.sm4_cbc_encrypt_update(ctx.sm4_cbc_ctx, (*C.uchar)(unsafe.Pointer(&in[0])), C.size_t(len(in)), (*C.uchar)(unsafe.Pointer(&outbuf[0])), &outlen) {
			return nil, errors.New("Libgmssl inner error")
		}
	} else {
		if 1 != C.sm4_cbc_decrypt_update(ctx.sm4_cbc_ctx, (*C.uchar)(unsafe.Pointer(&in[0])), C.size_t(len(in)), (*C.uchar)(unsafe.Pointer(&outbuf[0])), &outlen) {
			return nil, errors.New("Libgmssl inner error")
		}
	}
	return outbuf[:outlen], nil
}

func (ctx *SM4CBCContext) Finish() ([]byte, error) {
	outbuf := make([]byte, C.SM4_BLOCK_SIZE)
	var outlen C.size_t
	if ctx.encrypt {
		if 1 != C.sm4_cbc_encrypt_finish(ctx.sm4_cbc_ctx, (*C.uchar)(unsafe.Pointer(&outbuf[0])), &outlen) {
			return nil, errors.New("Libgmssl inner error")
		}
	} else {
		if 1 != C.sm4_cbc_decrypt_finish(ctx.sm4_cbc_ctx, (*C.uchar)(unsafe.Pointer(&outbuf[0])), &outlen) {
			return nil, errors.New("Libgmssl inner error")
		}
	}
	return outbuf[:outlen], nil
}


type SM4CTRContext struct {
	sm4_ctr_ctx *C.SM4_CTR_CTX
}

func NewSM4CTRContext(key []byte, iv []byte) (*SM4CTRContext, error) {
	if key == nil {
		return nil, errors.New("No key")
	}
	if len(key) != int(C.SM4_KEY_SIZE) {
		return nil, errors.New("Invalid key length")
	}
	if len(iv) != int(C.SM4_BLOCK_SIZE) {
		return nil, errors.New("Invalid IV length")
	}
	sm4_ctr_ctx := C.sm4_ctr_ctx_new()
	if sm4_ctr_ctx == nil {
		return nil, errors.New("Malloc failure")
	}
	ret := &SM4CTRContext{sm4_ctr_ctx}
	runtime.SetFinalizer(ret, func(ret *SM4CTRContext) {
		C.sm4_ctr_ctx_free(ret.sm4_ctr_ctx)
	})
	if 1 != C.sm4_ctr_encrypt_init(sm4_ctr_ctx, (*C.uchar)(unsafe.Pointer(&key[0])), (*C.uchar)(unsafe.Pointer(&iv[0]))) {
		return nil, errors.New("Libgmssl inner error")
	}
	return ret, nil
}

func (ctx *SM4CTRContext) Update(in []byte) ([]byte, error) {
	outbuf := make([]byte, len(in) + C.SM4_BLOCK_SIZE)
	var outlen C.size_t
	if 1 != C.sm4_ctr_encrypt_update(ctx.sm4_ctr_ctx, (*C.uchar)(&in[0]), C.size_t(len(in)), (*C.uchar)(&outbuf[0]), &outlen) {
		return nil, errors.New("Libgmssl inner error")
	}
	return outbuf[:outlen], nil
}

func (ctx *SM4CTRContext) Finish() ([]byte, error) {
	outbuf := make([]byte, C.SM4_BLOCK_SIZE)
	var outlen C.size_t
	if 1 != C.sm4_ctr_encrypt_finish(ctx.sm4_ctr_ctx, (*C.uchar)(&outbuf[0]), &outlen) {
		return nil, errors.New("Libgmssl inner error")
	}
	return outbuf[:outlen], nil
}


const Sm4GcmMinIvSize = 8
const Sm4GcmMaxIvSize = 64
const Sm4GcmDefaultIvSize = 64
const Sm4GcmDefaultTagSize = 16
const Sm4GcmMaxTagSize = 16

type SM4GCMContext struct {
	sm4_gcm_ctx *C.SM4_GCM_CTX
	encrypt bool
}

func NewSM4GCMContext(key []byte, iv []byte, aad []byte, taglen int, encrypt bool) (*SM4GCMContext, error) {
	if key == nil {
		return nil, errors.New("No key")
	}
	if len(key) != int(C.SM4_KEY_SIZE) {
		return nil, errors.New("Invalid key length")
	}
	if len(iv) < C.SM4_GCM_MIN_IV_SIZE || len(iv) > C.SM4_GCM_MAX_IV_SIZE {
		return nil, errors.New("Invalid IV length")
	}
	sm4_gcm_ctx := C.sm4_gcm_ctx_new()
	if sm4_gcm_ctx == nil {
		return nil, errors.New("Malloc failure")
	}
	ret := &SM4GCMContext{sm4_gcm_ctx, encrypt}
	runtime.SetFinalizer(ret, func(ret *SM4GCMContext) {
		C.sm4_gcm_ctx_free(ret.sm4_gcm_ctx)
	})
	if encrypt == true {
		if 1 != C.sm4_gcm_encrypt_init(sm4_gcm_ctx, (*C.uchar)(&key[0]), C.size_t(len(key)), (*C.uchar)(&iv[0]), C.size_t(len(iv)),
			(*C.uchar)(&aad[0]), C.size_t(len(aad)), C.size_t(taglen)) {
			return nil, errors.New("Libgmssl inner error")
		}
	} else {
		if 1 != C.sm4_gcm_decrypt_init(sm4_gcm_ctx, (*C.uchar)(&key[0]), C.size_t(len(key)), (*C.uchar)(&iv[0]), C.size_t(len(iv)),
			(*C.uchar)(&aad[0]), C.size_t(len(aad)), C.size_t(taglen)) {
			return nil, errors.New("Libgmssl inner error")
		}
	}
	return ret, nil
}

func (ctx *SM4GCMContext) Update(in []byte) ([]byte, error) {
	outbuf := make([]byte, len(in) + C.SM4_BLOCK_SIZE)
	var outlen C.size_t
	if ctx.encrypt {
		if 1 != C.sm4_gcm_encrypt_update(ctx.sm4_gcm_ctx, (*C.uchar)(&in[0]), C.size_t(len(in)), (*C.uchar)(&outbuf[0]), &outlen) {
			return nil, errors.New("Libgmssl inner error")
		}
	} else {
		if 1 != C.sm4_gcm_decrypt_update(ctx.sm4_gcm_ctx, (*C.uchar)(&in[0]), C.size_t(len(in)), (*C.uchar)(&outbuf[0]), &outlen) {
			return nil, errors.New("Libgmssl inner error")
		}
	}
	return outbuf[:outlen], nil
}

func (ctx *SM4GCMContext) Finish() ([]byte, error) {
	outbuf := make([]byte, C.SM4_BLOCK_SIZE*2) // FIXME: prepare different size of enc/dec,  enc need larger
	var outlen C.size_t
	if ctx.encrypt {
		if 1 != C.sm4_gcm_encrypt_finish(ctx.sm4_gcm_ctx, (*C.uchar)(&outbuf[0]), &outlen) {
			return nil, errors.New("Libgmssl inner error")
		}
	} else {
		if 1 != C.sm4_gcm_decrypt_finish(ctx.sm4_gcm_ctx, (*C.uchar)(&outbuf[0]), &outlen) {
			return nil, errors.New("Libgmssl inner error")
		}
	}
	return outbuf[:outlen], nil
}
