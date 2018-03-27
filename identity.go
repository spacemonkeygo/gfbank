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
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"os"
	"path/filepath"
)

type PassphraseFunc func(name string) (passphrase string, err error)

const DefaultIdentityName = "default"

type Identities struct {
	dir string
	fn  PassphraseFunc
}

func NewIdentities(dir string, fn PassphraseFunc) (*Identities, error) {
	ids := &Identities{
		dir: dir,
		fn:  fn,
	}

	err := os.MkdirAll(dir, 0755)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	// initialize default identity symlink if it does not exist
	default_path := ids.identPath(DefaultIdentityName)
	_, err = os.Lstat(default_path)
	if os.IsNotExist(err) {
		err = os.Symlink(resolvePath("~/.ssh/id_rsa"), default_path)
	}
	if err != nil {
		return nil, Error.Wrap(err)
	}

	return ids, nil
}

func (ids *Identities) Load(name string) (ident *Identity, err error) {
	return LoadIdentity(ids.identPath(name), ids.fn)
}

func (ids *Identities) identPath(name string) string {
	return filepath.Join(ids.dir, name)
}

type Identity struct {
	Name string
	Id   string
	Key  *rsa.PrivateKey
}

func LoadIdentity(path string, fn PassphraseFunc) (key *Identity, err error) {
	pem_bytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	var block *pem.Block
	for {
		block, pem_bytes = pem.Decode(pem_bytes)
		if block == nil {
			return nil, Error.New("private key not found")
		}
		if block.Type == "RSA PRIVATE KEY" {
			break
		}
	}

	key_bytes := block.Bytes
	if x509.IsEncryptedPEMBlock(block) {
		if fn == nil {
			return nil, Error.New("private key is encrypted")
		}
		passphrase, err := fn(filepath.Base(path))
		if err != nil {
			return nil, Error.Wrap(err)
		}
		key_bytes, err = x509.DecryptPEMBlock(block, []byte(passphrase))
		if err != nil {
			return nil, Error.Wrap(err)
		}
	}

	privkey, err := x509.ParsePKCS1PrivateKey(key_bytes)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	keyid, err := publicKeyId(&privkey.PublicKey)
	if err != nil {
		return nil, err
	}

	return &Identity{
		Name: filepath.Base(path),
		Id:   keyid,
		Key:  privkey,
	}, nil
}

func (id *Identity) DecryptShare(encrypted_share *EncryptedShare) (
	*Share, error) {

	enc_data, err := base64Decode(encrypted_share.Data)
	if err != nil {
		return nil, err
	}

	// `go vet` caught a bug with the way share labels were generated
	// (incorrect format specifier). The bug is fixed but since the label is
	// part of the signed payload, first try to decrypt with the correct share
	// label and if that fails try again with the broken share label.
	data, err := rsa.DecryptOAEP(sha256.New(), rand.Reader,
		id.Key, enc_data, shareLabel(encrypted_share.Number))
	if err != nil {
		var err_broken error
		if data, err_broken = rsa.DecryptOAEP(
			sha256.New(), rand.Reader, id.Key, enc_data,
			brokenShareLabel(encrypted_share.Number)); err_broken != nil {
			// return the original error
			return nil, Error.Wrap(err)
		}
	}

	return &Share{
		Number: encrypted_share.Number,
		Data:   data,
	}, nil
}
