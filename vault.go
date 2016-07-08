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
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"
)

type Vaults struct {
	dir string
}

func NewVaults(dir string) (*Vaults, error) {
	err := os.MkdirAll(dir, 0755)
	if err != nil {
		return nil, Error.Wrap(err)
	}
	return &Vaults{
		dir: dir,
	}, nil
}

func (vs *Vaults) Load(name string) (vault *Vault, err error) {
	return LoadVault(vs.vaultPath(name))
}

func (vs *Vaults) List() ([]string, error) {
	return directoryFiles(vs.dir)
}

func (vs *Vaults) LoadAll() (out []Vault, err error) {
	names, err := vs.List()
	if err != nil {
		return nil, err
	}
	for _, name := range names {
		vault, err := vs.Load(name)
		if err != nil {
			return nil, err
		}
		out = append(out, *vault)
	}
	return out, nil
}

func (vs *Vaults) Create(src string, pubkeys []PublicKey, n, m int) (
	*Vault, error) {

	name := vaultName(src)

	data, err := ioutil.ReadFile(src)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	vault, err := CreateVault(name, data, pubkeys, n, m)
	if err != nil {
		return nil, err
	}

	err = vault.Save(vs.vaultPath(name))
	if err != nil {
		return nil, err
	}

	return vault, nil
}

func (vs *Vaults) vaultPath(name string) string {
	return filepath.Join(vs.dir, name)
}

type EncryptedShare struct {
	Identity string `json:"identity"`
	KeyId    string `json:"keyid"`
	Number   string `json:"number"`
	Data     string `json:"data"`
}

type Vault struct {
	Name   string           `json:"-"`
	Nonce  string           `json:"nonce"`
	Needed int              `json:"needed"`
	Shares []EncryptedShare `json:"shares"`
	Data   string           `json:"data"`
}

func LoadVault(path string) (vault *Vault, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, Error.Wrap(err)
	}
	defer f.Close()

	vault = &Vault{}
	err = json.NewDecoder(f).Decode(vault)
	if err != nil {
		return nil, Error.Wrap(err)
	}
	vault.Name = vaultName(path)

	return vault, nil
}

func (v *Vault) Open(key_shares []Share) ([]byte, error) {
	key, err := CombineBytes(key_shares)
	if err != nil {
		return nil, err
	}

	nonce, err := base64Decode(v.Nonce)
	if err != nil {
		return nil, err
	}

	encrypted_data, err := base64Decode(v.Data)
	if err != nil {
		return nil, err
	}

	return DecryptBytes(encrypted_data, key, nonce)
}

func (v *Vault) Save(path string) (err error) {
	json_bytes, err := json.MarshalIndent(v, "", "\t")
	if err != nil {
		return Error.Wrap(err)
	}

	err = ioutil.WriteFile(path, json_bytes, 0600)
	if err != nil {
		return Error.Wrap(err)
	}

	return nil
}

func (v *Vault) LookupKeyId(keyid string) *EncryptedShare {
	for _, share := range v.Shares {
		if share.KeyId == keyid {
			return &share
		}
	}
	return nil
}

func (v *Vault) Audit(keyids *KeyIds) VaultAudit {
	var shares []ShareAudit
	for _, share := range v.Shares {
		shares = append(shares, ShareAudit{
			Number:   share.Number,
			Identity: share.Identity,
			KeyId:    share.KeyId,
			Safe:     keyids.Has(share.KeyId),
		})
	}

	return VaultAudit{
		Name:   v.Name,
		Needed: v.Needed,
		Shares: shares,
	}
}

func CreateVault(name string, data []byte, pubkeys []PublicKey, n, m int) (
	vault *Vault, err error) {

	if n == 0 {
		return nil, Error.New("n cannot be zero")
	}

	if m == 0 {
		return nil, Error.New("m cannot be zero")
	}

	if n > m {
		return nil, Error.New("n cannot be greater than m")
	}

	if len(pubkeys) < m {
		return nil, Error.New("expected at least %d public keys; got %d",
			m, len(pubkeys))
	}

	encrypted_data, key, nonce, err := EncryptBytes(data)
	if err != nil {
		return nil, err
	}

	key_shares, err := SplitBytes(key, n, m)
	if err != nil {
		return nil, err
	}

	var enc_key_shares []EncryptedShare
	for i, share := range key_shares {
		enc_share, err := pubkeys[i].EncryptShare(share)
		if err != nil {
			return nil, err
		}
		enc_key_shares = append(enc_key_shares, *enc_share)
	}

	return &Vault{
		Name:   name,
		Needed: n,
		Nonce:  base64Encode(nonce),
		Shares: enc_key_shares,
		Data:   base64Encode(encrypted_data),
	}, nil
}

func vaultName(src string) string {
	return filepath.Base(src)
}
