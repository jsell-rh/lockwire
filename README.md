# Lockwire

Share your terminal. End-to-end encrypted. Zero config.

```
$ lw share
  ┏╸lockwire
  ┃
  ┃  code  thunder-eagle-river-moon-stone-fire
  ┃  link  https://lockwire.online/join#thunder-eagle-river-moon-stone-fire
  ┗╸

$
```

Someone else, anywhere:

```
$ lw join thunder-eagle-river-moon-stone-fire
```

Or just open the link in a browser. That's it.

## What it does

You run `lw share`. It gives you a six-word code. Anyone with that code can watch your terminal in real time, either from their own terminal or from a browser. They can't type anything or control your session. When you're done, type `lw stop` or just close your shell.

The relay server never sees your terminal content. It forwards encrypted blobs and has no access to keys. All crypto happens on your machine and the viewer's machine.

## Install

Download the binary for your platform from [releases](https://github.com/jsell-rh/lockwire/releases) and put it in your PATH.

```
# Linux (amd64)
curl -Lo lw https://github.com/jsell-rh/lockwire/releases/latest/download/lw-linux-amd64
chmod +x lw
sudo mv lw /usr/local/bin/
```

## Usage

**Share your terminal:**

```
lw share
```

**Watch someone's terminal (CLI):**

```
lw join thunder-eagle-river-moon-stone-fire
```

**Watch in a browser:**

Open the link printed by `lw share`. No install needed.

**See who's watching:**

```
lw viewers
```

**Kick someone:**

```
lw revoke <viewer-id>
```

**Stop sharing:**

```
lw stop
```

## Self-hosting the relay

Run your own relay with the container image:

```
docker run -p 8443:8443 ghcr.io/jsell-rh/lockwire
```

Then point clients at it:

```
lw share --relay wss://your-relay:8443 --relay-insecure
lw join <code> --relay wss://your-relay:8443 --relay-insecure
```

Use `--relay-insecure` with self-signed certs. For production, provide your own certs:

```
lw relay --tls-cert cert.pem --tls-key key.pem
```

## How it works

1. `lw share` generates a random six-word code and derives a session ID from it using Argon2id
2. The sharer and viewer perform a SPAKE2 handshake through the relay, proving they both know the code without revealing it
3. The handshake produces a shared secret used to derive AES-256-GCM encryption keys
4. Terminal output is encrypted and streamed through the relay. The relay forwards opaque blobs.
5. Keys rotate every 60 seconds. Revoking a viewer triggers an immediate key rotation so they lose access.

The relay is a blind pipe. It never touches key material, never decrypts content, and never stores anything to disk.

## Security

- AES-256-GCM encryption, SPAKE2 key agreement, HKDF key derivation
- All keys are held in memory only and zeroed on exit
- Password prompts (sudo, ssh) are safe because programs disable terminal echo for those
- The relay cannot read your terminal content
- No telemetry, no logs, no accounts

## Building from source

```
make setup   # install git hooks
make web     # build web viewer
make build   # build the lw binary
make test    # run tests with race detector
```

Requires Go 1.25+ and Node.js 22+.
