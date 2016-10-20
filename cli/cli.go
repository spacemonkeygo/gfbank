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

package gfbankcli

import (
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/jawher/mow.cli"
	"github.com/spacemonkeygo/errors"
	"github.com/spacemonkeygo/gfbank"
)

type ProxyMaker interface {
	NewProxy(args string) (gfbank.Proxy, error)
}

type ProxyMakerFunc func(args string) (gfbank.Proxy, error)

func (fn ProxyMakerFunc) NewProxy(args string) (gfbank.Proxy, error) {
	return fn(args)
}

func Run(args []string, proxy_maker ProxyMaker) {
	var bank *gfbank.Bank
	var err error

	if len(args) == 0 {
		args = append(args, "gfbank")
	}
	bin := filepath.Base(args[0])
	app := cli.App(bin, "The Grand French Bank")

	// global options
	dir_opt := app.StringOpt("dir", "./", "bank directory")
	debug_opt := app.BoolOpt("debug", false, "debug logging")
	identity_opt := app.StringOpt("identity", "default",
		"private key identity")
	var proxy_opt *bool
	var proxy_args_opt *string
	if proxy_maker != nil {
		proxy_opt = app.BoolOpt("proxy", true, "use proxy")
		proxy_args_opt = app.StringOpt("proxy_args", "", "proxy args")
	}

	var exite func(error, string, ...interface{})
	var errmsg func(error) string

	// initialize bank
	app.Before = func() {
		exite = func(err error, format string, args ...interface{}) {
			exitOnError(err, *debug_opt, format, args...)
		}
		errmsg = func(err error) string {
			return errorMessage(err, *debug_opt)
		}

		var proxy gfbank.Proxy
		if proxy_opt != nil && *proxy_opt {
			var err error
			proxy, err = proxy_maker.NewProxy(*proxy_args_opt)
			exite(err, "failed to create proxy")
		}

		bank, err = gfbank.NewBank(*dir_opt, *identity_opt, proxy,
			func(name string) (string, error) {
				return secureReadline(
					fmt.Sprintf("%s private key passphrase", name))
			})
		exite(err, "failed to initialize bank")
	}

	// key commands
	app.Command("pubkey", "public key commands", func(cmd *cli.Cmd) {
		cmd.Command("list", "list all public keys", func(cmd *cli.Cmd) {
			cmd.Action = func() {
				pubkeys, err := bank.LoadPublicKeys()
				exite(err, "unable to load public keys")
				if len(pubkeys) == 0 {
					fmt.Println("no public keys found.")
				} else {
					for _, pubkey := range pubkeys {
						fmt.Printf("%s %s\n", pubkey.Id, pubkey.Name)
					}
				}
			}
		})

		cmd.Command("revoke", "revoke public key", func(cmd *cli.Cmd) {
			cmd.Spec = "NAME"
			name_arg := cmd.StringArg("NAME", "", "public key to revoke")
			cmd.Action = func() {
				pubkey, err := bank.RevokePublicKey(*name_arg)
				exite(err, "unable to revoke public key %q", *name_arg)
				fmt.Printf("revoked %q.\n", *name_arg)
				fmt.Println("auditing impacted vaults...")
				audits, err := bank.AuditVaultsWithKeyId(pubkey.Id)
				exite(err, "unable to audit")
				printAudits(audits)
			}
		})

		cmd.Command("unrevoke", "unrevoke public key", func(cmd *cli.Cmd) {
			cmd.Spec = "NAME"
			name_arg := cmd.StringArg("NAME", "", "public key to unrevoke")
			cmd.Action = func() {
				pubkey, err := bank.UnrevokePublicKey(*name_arg)
				exite(err, "unable to unrevoke public key %q", *name_arg)
				fmt.Printf("unrevoked %q.\n", *name_arg)
				fmt.Println("auditing impacted vaults...")
				audits, err := bank.AuditVaultsWithKeyId(pubkey.Id)
				exite(err, "unable to audit")
				printAudits(audits)
			}
		})

		cmd.Command("import", "import a public key", func(cmd *cli.Cmd) {
			cmd.Spec = "FILES..."
			files_arg := cmd.StringsArg("FILES", nil, "input files")
			cmd.Action = func() {
				var failed bool
				for _, file := range *files_arg {
					pubkey, err := bank.ImportPublicKey(file)
					if err == nil {
						fmt.Printf("%s %s: imported\n", pubkey.Id, pubkey.Name)
					} else {
						fmt.Printf("unable to import %s: %s\n",
							filepath.Base(file), errmsg(err))
						failed = true
					}
				}
				if failed {
					cli.Exit(1)
				}
			}
		})
	})

	// vault commands
	app.Command("vault", "vault commands", func(cmd *cli.Cmd) {
		// list all vaults
		cmd.Command("list", "list vaults", func(cmd *cli.Cmd) {
			cmd.Action = func() {
				names, err := bank.ListVaults()
				exite(err, "unable to list vaults")
				for _, name := range names {
					fmt.Println(name)
				}
			}
		})

		// add a vault
		cmd.Command("create", "create vault", func(cmd *cli.Cmd) {
			cmd.Spec = "[OPTIONS] SRC PUBKEYS..."
			src_arg := cmd.StringArg("SRC", "", "file to seal in vault")
			pubkeys_arg := cmd.StringsArg("PUBKEYS", nil,
				"public keys used to encrypt the vault key")
			n_opt := cmd.IntOpt("n", 3,
				"number of shares needed to open vault")
			m_opt := cmd.IntOpt("m", 6,
				"number of vault key shares generated")
			cmd.Action = func() {
				vault, err := bank.CreateVault(*src_arg, *pubkeys_arg, *n_opt,
					*m_opt)
				exite(err, "unable to add vault")
				fmt.Printf("created %q.\n", vault.Name)
			}
		})

		// open a vault
		cmd.Command("open", "open vault", func(cmd *cli.Cmd) {
			cmd.Spec = "[OPTIONS] VAULT DEST"
			vault_arg := cmd.StringArg("VAULT", "", "vault to open")
			dest_arg := cmd.StringArg("DEST", "", "output destination")
			cmd.Action = func() {
				status := openStatus{bin: bin, vault_name: *vault_arg}
				err := bank.HostVaultOpen(*vault_arg, *dest_arg, status)
				exite(err, "unable to open vault")
				fmt.Printf("opened %q.\n", *vault_arg)
			}
		})

		// collude to open a vault
		cmd.Command("collude", "collude to open vault", func(cmd *cli.Cmd) {
			cmd.Spec = "[OPTIONS] VAULT HOST KEYID"
			vault_arg := cmd.StringArg("VAULT", "", "vault to open")
			host_arg := cmd.StringArg("HOST", "", "host to collude with")
			keyid_arg := cmd.StringArg("KEYID", "", "expected host keyid")
			cmd.Action = func() {
				err := bank.JoinVaultOpen(*vault_arg, *host_arg, *keyid_arg)
				exite(err, "unable to collude")
				fmt.Println("done.")
			}
		})

		// list all vaults
		cmd.Command("audit", "audit vaults", func(cmd *cli.Cmd) {
			cmd.Spec = "[OPTIONS] [VAULTS...]"
			vaults_arg := cmd.StringsArg("VAULTS", nil,
				"vaults to audit (all if empty)")
			verbose_opt := cmd.BoolOpt("v verbose", false,
				"verbose audit output")
			cmd.Action = func() {
				names := *vaults_arg
				var audits []gfbank.VaultAudit
				var err error
				if len(names) == 0 {
					audits, err = bank.AuditAllVaults()
				} else {
					audits, err = bank.AuditVaults(names)
				}
				exite(err, "unable to audit")
				if *verbose_opt {
					printVerboseAudits(audits)
				} else {
					printAudits(audits)
				}
			}
		})
	})

	exite(app.Run(os.Args), "app")
}

type openStatus struct {
	bin        string
	vault_name string
}

func (s openStatus) Started(host net.Addr, host_keyid string) {
	fmt.Println("join with:")
	fmt.Printf("    %s vault collude %s %s %s\n",
		s.bin, s.vault_name, host, host_keyid)
}

func (s openStatus) ShareReceived(keyid, num string, have, needed int) {
	fmt.Printf("received share %s from %s (%d of %d)\n",
		num, keyid, have, needed)
}

func (s openStatus) JoinFailed(err error) {
	fmt.Printf("join failed: %v\n", err)
}

func printAudits(audits []gfbank.VaultAudit) {
	var padding int
	for _, audit := range audits {
		if padding < len(audit.Name) {
			padding = len(audit.Name)
		}
	}

	statusfmt := fmt.Sprintf("%%%ds: %%s (%%d of %%d)\n", padding)
	for _, audit := range audits {
		fmt.Printf(statusfmt,
			audit.Name,
			auditStatusString(audit.Status()),
			audit.Safe(),
			len(audit.Shares))
	}
}

func printVerboseAudits(audits []gfbank.VaultAudit) {
	for a, audit := range audits {
		if a != 0 {
			fmt.Println()
		}
		fmt.Printf("[%s]\n", audit.Name)
		fmt.Printf("    status: %s\n", auditStatusString(audit.Status()))
		fmt.Printf("    needed: %d (of %d)\n", audit.Needed, len(audit.Shares))
		for s, share := range audit.Shares {
			if s == 0 {
				fmt.Printf("    shares: ")
			} else {
				fmt.Printf("            ")
			}
			if share.Safe {
				fmt.Printf("%s safe %s/%s\n",
					share.Number, share.KeyId, share.Identity)
			} else {
				fmt.Printf("%s lost %s/%s\n",
					share.Number, share.KeyId, share.Identity)
			}
		}
	}
}

func auditStatusString(status gfbank.AuditStatus) string {
	switch status {
	case gfbank.VaultOK:
		return "ok"
	case gfbank.VaultAtRisk:
		return "at risk"
	case gfbank.VaultLost:
		return "LOST"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", status)
	}
}

func errorMessage(err error, debug bool) string {
	if debug {
		return err.Error()
	} else {
		return errors.GetMessage(err)
	}
}

func exitOnError(err error, debug bool, format string, args ...interface{}) {
	if err == nil {
		return
	}
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintf(os.Stderr, "%s: %s\n", msg, errorMessage(err, debug))
	cli.Exit(1)
}
