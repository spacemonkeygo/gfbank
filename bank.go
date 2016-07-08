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
	"io/ioutil"
	"path/filepath"
)

type Bank struct {
	idents   *Identities
	pubkeys  *PublicKeys
	vaults   *Vaults
	identity string
	proxy    Proxy
}

func NewBank(dir, identity string, proxy Proxy, fn PassphraseFunc) (
	b *Bank, err error) {

	idents, err := NewIdentities(filepath.Join(dir, "identity"), fn)
	if err != nil {
		return nil, err
	}

	pubkeys, err := NewPublicKeys(filepath.Join(dir, "pubkeys"))
	if err != nil {
		return nil, err
	}

	vaults, err := NewVaults(filepath.Join(dir, "vaults"))
	if err != nil {
		return nil, err
	}

	return &Bank{
		idents:   idents,
		pubkeys:  pubkeys,
		vaults:   vaults,
		identity: identity,
		proxy:    proxy,
	}, nil
}

func (b *Bank) LoadPublicKeys() (keys []PublicKey, err error) {
	return b.pubkeys.LoadAll()
}

func (b *Bank) ImportPublicKey(path string) (*PublicKey, error) {
	return b.pubkeys.Import(path)
}

func (b *Bank) RevokePublicKey(name string) (*PublicKey, error) {
	return b.pubkeys.Revoke(name)
}

func (b *Bank) UnrevokePublicKey(name string) (*PublicKey, error) {
	return b.pubkeys.Unrevoke(name)
}

func (b *Bank) JoinVaultOpen(name, host, host_keyid string) (err error) {
	identity, err := b.idents.Load(b.identity)
	if err != nil {
		return err
	}

	vault, err := b.vaults.Load(name)
	if err != nil {
		return err
	}

	err = JoinVaultOpen(identity, vault, host, host_keyid, b.proxy)
	if err != nil {
		return err
	}
	return nil
}

func (b *Bank) ListVaults() (names []string, err error) {
	return b.vaults.List()
}

func (b *Bank) HostVaultOpen(name string, out string, status OpenStatus) (
	err error) {

	identity, err := b.idents.Load(b.identity)
	if err != nil {
		return err
	}

	vault, err := b.vaults.Load(name)
	if err != nil {
		return err
	}

	data, err := HostVaultOpen(identity, vault, b.proxy, status)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(out, data, 0600)
	if err != nil {
		return Error.Wrap(err)
	}
	return nil
}

func (b *Bank) CreateVault(src string, pubkeys []string, n, m int) (
	vault *Vault, err error) {

	chosen, err := b.pubkeys.LoadN(pubkeys)
	if err != nil {
		return nil, err
	}

	return b.vaults.Create(src, chosen, n, m)
}

func (b *Bank) AuditAllVaults() ([]VaultAudit, error) {
	names, err := b.vaults.List()
	if err != nil {
		return nil, err
	}
	return b.AuditVaults(names)
}

func (b *Bank) AuditVaultsWithKeyId(keyid string) (audits []VaultAudit,
	err error) {

	keyids, err := b.allKeyIds()
	if err != nil {
		return nil, err
	}

	vaults, err := b.vaults.LoadAll()
	if err != nil {
		return nil, err
	}

	for _, vault := range vaults {
		if vault.LookupKeyId(keyid) == nil {
			continue
		}
		audits = append(audits, vault.Audit(keyids))
	}

	return audits, nil
}

func (b *Bank) AuditVaults(names []string) (audits []VaultAudit, err error) {
	keyids, err := b.allKeyIds()
	if err != nil {
		return nil, err
	}

	for _, name := range names {
		vault, err := b.vaults.Load(name)
		if err != nil {
			return nil, err
		}
		audits = append(audits, vault.Audit(keyids))
	}
	return audits, nil
}

func (b *Bank) allKeyIds() (*KeyIds, error) {
	pubkeys, err := b.pubkeys.LoadAll()
	if err != nil {
		return nil, err
	}

	return PublicKeyIds(pubkeys), nil
}
