# gfbank

This tool manages on-disk "vaults" of secrets that require `n` of `m` SSH RSA
keys for decryption. This technique uses Shamir secret sharing via libgfshare.

When a vault is created, a secret file is encrypted with a new key, and then
the key is n of m Shamir secret shared to keys that are themselves encrypted
to the public ends of SSH RSA keys, and then all of this vault information is
stored on disk.

To decrypt the vault, gfbank will start a network server which the other `n-1`
key holders can use their SSH private keys to connect to. Once `n` users are
connected (including the server starter), the vault will be decrypted and the
secret restored.

## Key generation

Note that this tool requires RSA SSH keys. You can generate a usable key in
the format this tool will understand by running:

```
ssh-keygen -t rsa -m pem -f output-key
```

## Requirements

libgfshare-bin (for gfcombine/gfsplit)

## Usage

```
Usage: gfbank [OPTIONS] COMMAND [arg...]

The Grand French Bank

Options:
      --dir        bank directory (default "./")
      --debug      debug logging
      --identity   private key identity (default "default")

Commands:
  pubkey           public key commands
  vault            vault commands

Run 'gfbank COMMAND --help' for more information on a command.
```

```
Usage: gfbank pubkey COMMAND [arg...]

public key commands

Commands:
  list         list all public keys
  revoke       revoke public key
  unrevoke     unrevoke public key
  import       import a public key

Run 'gfbank pubkey COMMAND --help' for more information on a command.
```

```
Usage: gfbank vault COMMAND [arg...]

vault commands

Commands:
  list         list vaults
  create       create vault
  open         open vault
  collude      collude to open vault
  audit        audit vaults

Run 'gfbank vault COMMAND --help' for more information on a command.
```

## LICENSE

See LICENSE file for details.
