# Wallet API authentication

`qrl_walletd` writes a new token to `wallet_api.token` in its QRL directory at
each start. The directory is mode `0700` and the token file is mode `0600`.
Wallet API clients must read that file and send its contents in the
`x-qrl-wallet-token` gRPC metadata header on every call, including `UnlockWallet`.
Restarted daemons require clients to reload the token.

Treat the token file and all client-side copies as wallet credentials. Keep
copies owner-only (`0600` in a `0700` directory), and distribute them only over
authenticated, encrypted channels. Exclude them from web roots, source control,
container images, shared or synced folders, logs, and unencrypted backups.
NGINX and the REST proxy forward request headers and do not need token-file
access; do not relax file permissions for them.

If a token may have been exposed, block remote access and restart walletd to
rotate it, verify rejection of the old token, and replace client copies.
Editing or deleting the file does not revoke the running daemon's token.
Rotation cannot undo transactions or retract disclosed recovery seeds.

The default listener is `127.0.0.1:19010`. Only loopback IP addresses and
`localhost` are accepted; `localhost` binds to `127.0.0.1` without DNS lookup.
Non-loopback and wildcard listeners now fail at startup. Use a local encrypted
tunnel if remote access is required. The gRPC connection itself is plaintext.

The token grants access to all Wallet API methods. The wallet passphrase is
still required to unlock an encrypted wallet, but unlocking applies to all
clients. Any token holder can spend or retrieve recovery seeds while the wallet
is unlocked. Processes running as the same OS user can read the token file.
