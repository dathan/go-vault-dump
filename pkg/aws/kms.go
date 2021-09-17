package aws

/*
 *  This file contains code adapted from https://github.com/DonMills/kmsencrypt
 *
 *  Copyright (c) 2016 Don Mills
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a copy
 *  of this software and associated documentation files (the "Software"), to deal
 *  in the Software without restriction, including without limitation the rights
 *  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *  copies of the Software, and to permit persons to whom the Software is
 *  furnished to do so, subject to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be included in all
 *  copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 *  SOFTWARE.
 */

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
)

const (
	kmsApp    = "vault-dump"
	kmsCipher = "AES_256"
)

func Encrypt(plaintext string, kmsKey string, region string) (string, error) {

	// get data encryption keys from KMS4
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(region),
	})
	if err != nil {
		return "", err
	}
	kmssvc := kms.New(sess)
	params := &kms.GenerateDataKeyInput{
		KeyId: aws.String(kmsKey),
		EncryptionContext: map[string]*string{
			"Application": aws.String(kmsApp),
		},
		KeySpec: aws.String(kmsCipher),
	}
	resp, err := kmssvc.GenerateDataKey(params)
	if err != nil {
		return "", err
	}
	plainkey := resp.Plaintext
	cipherkey := resp.CiphertextBlob

	// generate salt
	salt := make([]byte, aes.BlockSize)
	_, err = rand.Read(salt)
	if err != nil {
		return "", err
	}

	// apply pkcs#7 padding tp plaintext
	padding := aes.BlockSize - (len(plaintext) % aes.BlockSize)
	paddedtext := []byte(plaintext)
	for i := 0; i < padding; i++ {
		paddedtext = append(paddedtext, byte(padding))
	}

	// encrypt padded plaintext
	ciphertext := make([]byte, len(paddedtext))
	c, err := aes.NewCipher(plainkey)
	if err != nil {
		return "", err
	}
	mode := cipher.NewCBCEncrypter(c, salt)
	mode.CryptBlocks(ciphertext, paddedtext)

	// combine metadata with ciphertext and base64 encode
	sep := []byte(kmsApp)
	bufferslice := [][]byte{cipherkey, salt, ciphertext}
	data := bytes.Join(bufferslice, sep)
	encodelen := base64.RawStdEncoding.EncodedLen(len(data))
	encrypted := make([]byte, encodelen)
	base64.RawStdEncoding.Encode(encrypted, data)

	return string(encrypted), nil
}
