// Copyright (C) 2016 Space Monkey, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package gfbank

import (
	"crypto/rand"

	"golang.org/x/crypto/nacl/secretbox"
)

func EncryptBytes(in []byte) (out, key, nonce []byte, err error) {
	var sb_key [32]byte
	_, err = rand.Read(sb_key[:])
	if err != nil {
		return nil, nil, nil, Error.Wrap(err)
	}

	var sb_nonce [24]byte
	_, err = rand.Read(sb_nonce[:])
	if err != nil {
		return nil, nil, nil, Error.Wrap(err)
	}

	return secretbox.Seal(nil, in, &sb_nonce, &sb_key),
		sb_key[:], sb_nonce[:], nil
}

func DecryptBytes(in, key, nonce []byte) (out []byte, err error) {
	var sb_key [32]byte
	if copy(sb_key[:], key) != len(sb_key) {
		return nil, Error.New("not enough key bytes: got %d expected %d",
			len(key), len(sb_key))
	}
	var sb_nonce [24]byte
	if copy(sb_nonce[:], nonce) != len(sb_nonce) {
		return nil, Error.New("not enough nonce bytes: got %d expected %d",
			len(nonce), len(sb_nonce))
	}

	out, ok := secretbox.Open(nil, in, &sb_nonce, &sb_key)
	if !ok {
		return nil, Error.New("secretbox open failed")
	}
	return out, nil
}
