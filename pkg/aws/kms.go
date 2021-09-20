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
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

const (
	kmsApp    = "vault-dump"
	kmsCipher = types.DataKeySpecAes256
)

func KMSEncrypt(plaintext string, kmsKey string, region string) (string, error) {

	// get data encryption keys from KMS
	cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion(region))
	if err != nil {
		return "", err
	}
	kmssvc := kms.NewFromConfig(cfg)

	params := &kms.GenerateDataKeyInput{
		KeyId:   aws.String(kmsKey),
		KeySpec: kmsCipher,
	}
	resp, err := kmssvc.GenerateDataKey(context.TODO(), params)
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
	data := []byte(plaintext)
	padding := aes.BlockSize - (len(data) % aes.BlockSize)
	for ii := 0; ii < padding; ii++ {
		data = append(data, byte(padding))
	}

	// encrypt padded plaintext
	c, err := aes.NewCipher(plainkey)
	if err != nil {
		return "", err
	}
	mode := cipher.NewCBCEncrypter(c, salt)
	mode.CryptBlocks(data, data)

	// combine metadata with ciphertext and base64 encode
	sep := []byte{0, 1, 0, 1, 0, 1}
	bufferslice := [][]byte{cipherkey, salt, data}
	combined := bytes.Join(bufferslice, sep)
	encoded := base64.URLEncoding.EncodeToString(combined)

	return encoded, nil
}

func KMSDecrypt(ciphertext string, region string) (string, error) {

	// split metadata and ciphertext
	decoded, err := base64.URLEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}
	sep := []byte{0, 1, 0, 1, 0, 1}
	sliced := bytes.SplitN(decoded, sep, 3)
	cipherkey := sliced[0]
	salt := sliced[1]
	data := sliced[2]

	// decrypt decryption key
	cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion(region))
	if err != nil {
		return "", err
	}
	kmssvc := kms.NewFromConfig(cfg)

	keyparams := &kms.DecryptInput{
		CiphertextBlob: cipherkey,
	}
	response, err := kmssvc.Decrypt(context.TODO(), keyparams)
	if err != nil {
		return "", err
	}

	plainkey := response.Plaintext

	// decrypt data
	block, err := aes.NewCipher(plainkey)
	if err != nil {
		return "", err
	}
	mode := cipher.NewCBCDecrypter(block, salt)
	mode.CryptBlocks(data, data)

	// remove pkcs#7 padding
	if len(data) == 0 {
		return "", errors.New("Empty payload")
	}
	padding := data[len(data)-1]

	if int(padding) > len(data) || int(padding) > aes.BlockSize {
		return "", errors.New(fmt.Sprintf("Padding %d larger than block size %d or data %d", padding, aes.BlockSize, len(data)))
	} else if padding == 0 {
		return "", errors.New("Does not contain proper padding")
	}
	for ii := len(data) - 1; ii > len(data)-int(padding)-1; ii-- {
		if data[ii] != padding {
			return "", errors.New("Padded value larger than padding")
		}
	}

	return string(data[:len(data)-int(padding)]), nil
}
