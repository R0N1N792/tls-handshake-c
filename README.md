# tls-handshake-c

## Overview

This is a learning project of TLS-like handshake + encrypted 
file transfer in C with libsodium. The project uses X25519(crypto_kx) + ChaCha20-Poly1305 and communication over TCP.
This project is **not** an implementation of **RFC 8446** and is **not** intended for production use 

## How it works

```
Client                                                          Server
   +--------------------------------------------------------------+
   |                                                              |
   |                                                              |
   | -------------------- client pk (32 B) -------------------->  |
   |                                                              |
   |                                                              |
   |  <------------------ server pk (32 B) ---------------------- |
   |                                                              |
   |                                                              |
   | [derive rx/tx]                               [derive rx/tx]  |
   |                                                              |
   |         [sending next two messages as plaintext]             |
   |                    [not encrypted]                           |
   |                                                              |
   | ----- sending "FILE: " + filename + '\0' (max 300 B) ----->  |
   |                                                              |
   |                                                              |
   | --------- sending ASCII digits + '\n' (variable) --------->  |
   |                                                              |
   |               [ while there are still batches ]              |
   |                        [ of the file ]                       |
   |                                                              |
   | ----- encrypted batch of the file (1 KiB + 16 B tag) ------> |
   |                                                              |
   |                     [ end of the loop ]                      |
   |                                                              |
   |                                                              |
   |  <---------- ACK: total bytes written (8 B, once) ---------- |
   |                                                              |
   |                                                              |
   +--------------------------------------------------------------+
```
The transfer begins with an asymmetric key exchange between the client and the server. The server listens on the default IP address and port, both defined as macros in `net.h`. The client never calls `bind()` — its local port is assigned by the operating system on `connect()` — but it reads those same macros to locate the server

### Client's side

Before the key exchange, the client resolves the file to be sent. The filename comes from `argv[1]`, or, if no argument is given, from a prompt on stdin. The client then calls `stat()` to confirm that the file exists and to read its size, which is needed for a later message; if the file is missing, the program exits with a failure code

The client creates a TCP socket by calling `get_tcp_socket()`

Afterward, it fills in the server address with `get_server_addr()`, using the `DEFAULT_SERVER_IP` and `DEFAULT_SERVER_PORT` macros from `net.h`, and connects to it

Now the client generates an ephemeral `(pk, sk)` keypair by calling `generate_keypair()` and sends the public key (pk) to the server over the established connection. A fresh keypair is generated for every connection, and it is used only for the key exchange — it never encrypts any of the transferred data

### Server's side

The server first enters its output directory: it calls `chdir()` on the path given as `argv[1]`, falling back to the current directory. Every received file is written there

Right after, it creates a passive socket for listening by calling `tcp_server_init()`, which performs the socket creation, `bind()` and `listen()` steps in one call

`tcp_accept()` then blocks until a client connects and returns a new active socket, which handles the session with that client

The server generates an ephemeral `(pk, sk)` keypair of its own by calling `generate_keypair()`, but the order on the wire is reversed compared to the client: it reads the client's public key first and only then sends its own

### What protocol is used in asymmetric key exchange

`generate_keypair()` is a wrapper around the libsodium function `crypto_kx_keypair()`. That function does only two things: it fills the secret key with 32 bytes from the CSPRNG via `randombytes_buf()`, and it derives the public key from that secret with `crypto_scalarmult_base()`, a scalar multiplication of the curve25519 base point. The secret key is stored as the raw random bytes — the X25519 scalar clamping is applied internally on every use rather than once at generation

Because the base point is fixed and known in advance, this multiplication cannot fail, so `generate_keypair()` always succeeds. Deriving the session keys can fail: `derive_client_keys()` and `derive_server_keys()` wrap `crypto_kx_client_session_keys()` and `crypto_kx_server_session_keys()`, which return -1 if the peer's public key is not acceptable

### Deriving session keys can fail

The functions give us `-1` only if the shared secret is zero. It happens for points of small order and defends against forcing the secret by an adversary, not against impersonation. An adversary can still force the shared secret to zero by sending a point of small order, which would hand them the session keys — but both sides see `-1` and close the connection first

### Session keys

The session keys live in the structure `session_keypair_t`. This structure has two keys `rx` and `tx` of length `SESSION_KEY_LEN` (32 bytes). Both the server and the client have the session keys and client's `tx` is equal to server's `rx` (the same for server's `tx` and client's `rx`, but in this project only the client talks with encrypted messages to the server so we don't use them). Why do we need two keys for session to receive and to send? With only one session key for symmetric encryption, an adversary can intercept a client-to-server record and reflect the record to the client as "server's response".The client would decrypt it with a valid tag. That's why we create two separate keys

### Sending the file

First of all, we send as plaintext `FILE: <name>\0` and the file size

`fread()` reads the file by blocks of size `BATCH_SIZE` (1024 bytes), each block is encrypted individually with ChaCha20-Poly1305. We send the block as the concatenation `ciphertext || tag`. The output is longer by 16 bytes (because of the tag). That's why `encrypted_buf` has size `BATCH_SIZE + AEAD_TAG_LEN` (1024 + 16 bytes)

The nonce has a length of 12 bytes and is created by calling `make_nonce()`. This function puts the counter in the nonce in a right-aligned way (the counter fits in the last 8 bytes of the nonce, the first 4 bytes remain zeros). We don't exchange the nonce, each side computes its nonce locally by incrementing the counter on sending/receiving the message

On the final read of the file, the client reads only `n` bytes (for `n` <= `BATCH_SIZE`) and sends `n` + `AEAD_TAG_LEN` bytes

To prevent leakage of the plaintext, we call `sodium_memzero(buf, BATCH_SIZE)`. If we used `memset()` in our code, the compiler has the right to perceive `memset()` as a dead store and just ignore it. As a consequence, we can face the leak into a core dump or a swap file, or through another bug that reveals memory

### Receiving and acknowledging

The server receives the `FILE: <name>\0` and the file size as plaintext. `read_until()` reads byte by byte until `\0` for the header and `\n` for the size. Then we validate the format of the header `FILE: `. All readings are performed in terms of one call of `read_until()`, unlike the body of the file where we read it by blocks of the **computed** length (see below) 

The file is saved under the formatted path where we leave the path just after the last `\`, `/` or `:`. `.`, `..` and empty strings are rejected (the defense against path traversal attacks)

The program doesn't have a length-prefix, so the server derives the size to read from `file_size` (that we received at the start of the conversation as plaintext): `BATCH_SIZE` + `AEAD_TAG_LEN` while we receive the whole block (1024 + 16 bytes). For the final block, the server derives `file_size` - `total` + `AEAD_TAG_LEN`

The server mirrors the client's counter and outputs the same nonce. It decrypts the message with `shared -> rx`, writes with `fwrite()` and loops while `total < file_size`

An ACK is sent only at the end. It carries the number of written bytes (8 bytes, big-endian with `put_u64_be`). The client reads the ACK with `get_u64_be` and compares it to the sent length

## Build

The only prerequisites are CMake 3.14 or newer and a C11 compiler. **Do not install libsodium** — `FetchContent` clones `robinlinden/libsodium-cmake` at a pinned commit and builds it as part of the project, so nothing has to be present system-wide. The commit is pinned rather than tracking a branch to keep the build reproducible; the first configure therefore needs `git` and a network connection

```bash
cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure
```

`--test-dir` needs CMake 3.20 or newer; with an older one, run `ctest` from inside the build directory. The suite is registered with CTest as `test_crypto`

Where the binaries land depends on the generator: single-config ones (Make, Ninja) use `build/`, multi-config ones (Visual Studio) use `build/Debug/` and need `--config Debug` on the build step. CLion uses its own `cmake-build-debug/`

```bash
./build/server ./received      # output directory; defaults to the current one
./build/client ./notes.txt     # file to send; prompted for if omitted
```

The address and port are not arguments — they come from `DEFAULT_SERVER_IP` and `DEFAULT_SERVER_PORT` in `net.h`, so changing them means editing the header and rebuilding

Verified on Windows with MinGW GCC and CMake 4.2.2: a clean configure and build from scratch, no warnings from `src/` or `test/` under `-Wall -Wextra -Wpedantic`, and `ctest` passing. The AES-256-GCM tests are skipped on CPUs without AES-NI, so the suite reports 7 assertions rather than 11

## Project layout

### Tree

```
CMakeLists.txt     build definition; fetches and builds libsodium
main.c             placeholder for the tls_handshake_c target
src/
  crypto.h/.c      key and session types, length macros, wrappers over libsodium
  net.h/.c         platform block, socket setup, full-buffer send and read
  byteorder.h      put_u64_be / get_u64_be, used for the ACK
  client.c         client entry point
  server.c         server entry point
test/
  test_utils.h     the CHECK and CHECK_TEST macros
  test_crypto.c    the suite for crypto.c
```

### Targets

`main.c` doesn't do anything; the real entry points are `client.c` and `server.c`

`crypto_lib` links sodium as PUBLIC, which is how `client.c` can just write `#include <sodium.h>`

`net_lib` doesn't link anything: `net.c` needs only platform sockets

`test_crypto` links only `crypto_lib`; the tests for crypto are implemented, but not for the network

## Security limitations

In our threat model we consider as an adversary the person/program that can read or change the traffic between the server and the client

### What program can't do 
The program is not meant to preserve Authenticity. We can clearly see that in our code we don't use any kind of certificates, so the program is vulnerable to impersonation attacks. The adversary can perform MITM (Man In The Middle) Attack, when server and client receive message "Handshake is done", but the whole traffic passes through the attacker. They make two sessions, the first: they create the session with the client, impersonating the server; the second: they create the session with the server, impersonating the client 

Integrity isn't preserved for the plaintext exchange (filename and filesize) that we don't encrypt, the same for ACK. The adversary can potentially change those values

The server can be occupied by one client, there's no timeout, and there's only one thread for the server

### What program can do

X25519 with ephemeral keys: both sides receive one secret that a passive listener cannot compute; if the keys are used once and will be wiped - forward secrecy

BLAKE2b turns that secret into two separate keys for symmetric encryption (rx, tx)

ChaCha20 gives Confidentiality of the file's body

Poly1305 (the tag) provides with Integrity of each record
