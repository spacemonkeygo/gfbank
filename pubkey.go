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
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/crypto/ssh"
)

type PublicKeys struct {
	dir string
}

func NewPublicKeys(dir string) (*PublicKeys, error) {
	ks := &PublicKeys{
		dir: dir,
	}
	err := os.MkdirAll(ks.revokedPath(""), 0755)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	return ks, nil
}

func (ks *PublicKeys) Revoke(name string) (*PublicKey, error) {
	return renameAndLoad(ks.keyPath(name), ks.revokedPath(name))
}

func (ks *PublicKeys) Unrevoke(name string) (*PublicKey, error) {
	return renameAndLoad(ks.revokedPath(name), ks.keyPath(name))
}

func renameAndLoad(src, dst string) (*PublicKey, error) {
	err := os.Rename(src, dst)
	if err != nil {
		return nil, Error.Wrap(err)
	}
	return LoadPublicKey(dst)
}

func (ks *PublicKeys) Import(path string) (key *PublicKey, err error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	split := strings.SplitN(string(data), " ", 2)
	if len(split) == 1 {
		return nil, Error.New("malformed public key text: missing preamble")
	}

	switch split[0] {
	case "ssh-rsa":
	default:
		return nil, Error.New("unsupported key type: %q", split[0])
	}

	name := publicKeyName(path)

	keypath := ks.keyPath(name)
	tmppath := keypath + ".tmp"
	defer func() {
		os.Remove(tmppath)
	}()

	err = ioutil.WriteFile(tmppath, data, 0644)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	key, err = LoadPublicKey(tmppath)
	if err != nil {
		return nil, err
	}
	key.Name = name

	err = os.Rename(tmppath, ks.keyPath(name))
	if err != nil {
		return nil, Error.Wrap(err)
	}

	return key, nil
}

func (ks *PublicKeys) Load(name string) (key *PublicKey, err error) {
	return LoadPublicKey(ks.keyPath(name))
}

func (ks *PublicKeys) LoadN(names []string) (out []PublicKey, err error) {
	for _, name := range names {
		key, err := ks.Load(name)
		if err != nil {
			return nil, err
		}
		out = append(out, *key)
	}
	return out, nil
}

func (ks *PublicKeys) LoadAll() (out []PublicKey, err error) {
	names, err := directoryFiles(ks.dir)
	if err != nil {
		return nil, err
	}
	return ks.LoadN(names)
}

func (ks *PublicKeys) keyPath(name string) string {
	return filepath.Join(ks.dir, name)
}

func (ks *PublicKeys) revokedPath(name string) string {
	return filepath.Join(ks.dir, "revoked", name)
}

type KeyIds struct {
	ids map[string]struct{}
}

func PublicKeyIds(keys []PublicKey) *KeyIds {
	ids := map[string]struct{}{}
	for _, key := range keys {
		ids[key.Id] = struct{}{}
	}
	return &KeyIds{ids: ids}
}

func (k *KeyIds) Has(keyid string) bool {
	_, ok := k.ids[keyid]
	return ok
}

type PublicKey struct {
	Name string
	Id   string
	Key  *rsa.PublicKey
}

func LoadPublicKey(path string) (*PublicKey, error) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd := exec.Command("ssh-keygen", "-e", "-m", "PKCS8", "-f", path)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		return nil, Error.New("ssh-keygen failed: %s", stderr)
	}

	// ssh-keygen output is a single PEM block with the PKIX formatted key
	block, _ := pem.Decode(stdout.Bytes())
	pkixkey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, Error.Wrap(err)
	}
	pubkey, ok := pkixkey.(*rsa.PublicKey)
	if !ok {
		return nil, Error.New("not an RSA public key")
	}

	keyid, err := publicKeyId(pubkey)
	if err != nil {
		return nil, err
	}

	return &PublicKey{
		Name: filepath.Base(path),
		Id:   keyid,
		Key:  pubkey,
	}, nil
}

func (k *PublicKey) EncryptShare(share Share) (*EncryptedShare, error) {
	data, err := rsa.EncryptOAEP(sha256.New(), rand.Reader,
		k.Key, share.Data, shareLabel(share.Number))
	if err != nil {
		return nil, Error.Wrap(err)
	}
	return &EncryptedShare{
		Identity: k.Name,
		KeyId:    k.Id,
		Number:   share.Number,
		Data:     base64Encode(data),
	}, nil
}

func publicKeyId(pubkey *rsa.PublicKey) (string, error) {
	ssh_key, err := ssh.NewPublicKey(pubkey)
	if err != nil {
		return "", Error.Wrap(err)
	}

	key_data := ssh_key.Marshal()
	key_data = bytes.TrimPrefix(key_data, []byte(ssh_key.Type()))
	sum := md5.Sum(key_data)
	return "md5:" + hexFingerprint(sum[:]), nil
}

func publicKeyName(path string) string {
	basename := filepath.Base(path)
	ext := filepath.Ext(basename)
	return basename[0 : len(basename)-len(ext)]
}

var twoXtwo = regexp.MustCompile("[[:xdigit:]]{2}")

func hexFingerprint(x []byte) string {
	hx := twoXtwo.ReplaceAllString(hex.EncodeToString(x), "$0:")
	if hx == "" {
		return hx
	}
	return hx[:len(hx)-1]
}
