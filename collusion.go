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
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/rpc"
	"time"

	"github.com/spacemonkeygo/errors"
)

var (
	rpcError = errors.NewClass("rpc", errors.NoCaptureStack())
)

type OpenStatus interface {
	Started(host net.Addr, keyid string)
	ShareReceived(keyid, number string, have, needed int)
	JoinFailed(err error)
}

func HostVaultOpen(identity *Identity, vault *Vault, proxy ListenProxy,
	status OpenStatus) (data []byte, err error) {

	var listener net.Listener
	if proxy == nil {
		listener, err = net.Listen("tcp", ":0")
	} else {
		listener, err = proxy.Listen()
	}
	if err != nil {
		return nil, Error.Wrap(err)
	}
	defer listener.Close()

	// Create self-signed TLS server config and wrap listener
	config, err := makeTLSConfig(identity, true)
	if err != nil {
		return nil, err
	}
	listener = tls.NewListener(listener, config)

	status.Started(listener.Addr(), identity.Id)

	// Keep accepting shares until there is enough to reconstruct the key
	var shares []Share
	for len(shares) < vault.Needed {
		conn, err := listener.Accept()
		if err != nil {
			status.JoinFailed(err)
			continue
		}
		tls_conn := conn.(*tls.Conn)

		err = tls_conn.Handshake()
		if err != nil {
			tls_conn.Close()
			status.JoinFailed(err)
			continue
		}

		handler := &collusionHandler{
			conn:   tls_conn,
			vault:  vault,
			shares: shares,
			status: status}
		server := rpc.NewServer()
		server.RegisterName("Collusion", handler)
		server.ServeConn(conn)
		shares = handler.shares
		conn.Close()
	}

	return vault.Open(shares)
}

func JoinVaultOpen(identity *Identity, vault *Vault, host, host_keyid string,
	proxy DialProxy) (err error) {

	enc_share := vault.LookupKeyId(identity.Id)
	if enc_share == nil {
		return Error.New("no share found for keyid %s", identity.Id)
	}

	share, err := identity.DecryptShare(enc_share)
	if err != nil {
		return err
	}

	config, err := makeTLSConfig(identity, false)
	if err != nil {
		return err
	}

	var conn net.Conn
	if proxy == nil {
		conn, err = net.Dial("tcp", host)
	} else {
		conn, err = proxy.Dial(host)
	}
	if err != nil {
		return Error.Wrap(err)
	}
	defer conn.Close()

	// perform the tls handshake
	tls_conn := tls.Client(conn, config)
	err = tls_conn.Handshake()
	if err != nil {
		return err
	}

	// closing the client closes the connection
	client := rpc.NewClient(tls_conn)
	defer client.Close()

	// make sure the server is expected
	keyid, err := getPublicKeyId(tls_conn)
	if err != nil {
		return err
	}
	if keyid != host_keyid {
		return Error.New("expected host keyid %s; got %s", host_keyid, keyid)
	}

	var response struct{}
	err = client.Call("Collusion.Join", *share, &response)
	if err != nil {
		return Error.Wrap(err)
	}

	return nil
}

type collusionHandler struct {
	conn   *tls.Conn
	vault  *Vault
	shares []Share
	status OpenStatus
}

func (c *collusionHandler) Join(share *Share, _ *struct{}) (err error) {
	defer func() {
		if err != nil {
			c.status.JoinFailed(err)
			err = nil
		}
	}()

	keyid, err := getPublicKeyId(c.conn)
	if err != nil {
		return err
	}

	enc_share := c.vault.LookupKeyId(keyid)
	if enc_share == nil {
		return rpcError.New("%s has no share in vault", keyid)
	}

	if enc_share.Number != share.Number {
		return rpcError.New("%s sent wrong share: expected %s; got %s",
			enc_share.Number, share.Number)
	}

	for _, existing_share := range c.shares {
		if existing_share.Number == share.Number {
			return rpcError.New("share %s already received", share.Number)
		}
	}

	c.shares = append(c.shares, *share)
	c.status.ShareReceived(keyid, share.Number, len(c.shares), c.vault.Needed)
	return nil
}

func getPublicKeyId(conn *tls.Conn) (string, error) {
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return "", rpcError.New("missing peer certificates")
	}
	if len(certs) > 1 {
		return "", rpcError.New("too many peer certificates: %d", len(certs))
	}

	cert := certs[0]
	pubkey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return "", rpcError.New("expected RSA public key")
	}

	return publicKeyId(pubkey)
}

func makeTLSConfig(identity *Identity, server bool) (*tls.Config, error) {
	cert, err := makeSelfSignedCert(identity, server)
	if err != nil {
		return nil, err
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{
			{
				PrivateKey:  identity.Key,
				Certificate: [][]byte{cert.Raw},
				Leaf:        cert,
			},
		},
		InsecureSkipVerify: true,
	}

	if server {
		config.ClientAuth = tls.RequireAnyClientCert
	}
	return config, nil
}

func makeSelfSignedCert(identity *Identity, server bool) (
	cert *x509.Certificate, err error) {

	now := time.Now()

	tmpl := &x509.Certificate{
		SignatureAlgorithm: x509.SHA256WithRSA,
		SerialNumber:       big.NewInt(1),
		Subject: pkix.Name{
			CommonName: identity.Id,
		},
		NotBefore: now.Add(-time.Minute * 5),
		NotAfter:  now.Add(time.Minute * 5),
		KeyUsage: x509.KeyUsageKeyEncipherment |
			x509.KeyUsageDigitalSignature |
			x509.KeyUsageContentCommitment,
	}

	if server {
		tmpl.ExtKeyUsage = append(tmpl.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
	} else {
		tmpl.ExtKeyUsage = append(tmpl.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
	}

	der_bytes, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl,
		identity.Key.Public(), identity.Key)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	cert, err = x509.ParseCertificate(der_bytes)
	if err != nil {
		return nil, Error.Wrap(err)
	}
	return cert, nil
}
