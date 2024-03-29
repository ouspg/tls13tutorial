# TLS 1.3 protocol implementation in Rust

This is an educational project to learn about the TLS 1.3 protocol and the general challenges of implementing
binary-level
network protocols.

The project attempts to follow the standard [RFC8466](https://datatracker.ietf.org/doc/html/rfc8446) as closely as
possible in naming conventions and data structures when converting the standard into Rust implementation.

The implementation is not likely the most efficient in terms of performance, or might not apply all the best
cryptographic
practices (e.g. constant times).
It leaves cryptographic operations mostly for external libraries, and we just generate some cryptographically random
bits.

In this project, we are more interested in the TLS protocol at the byte level and how to implement decoders, create
functional tests for them and integrate fuzzing straight from the beginning.

Most of the data structures and their encoders have been provided. The logic to implement the complete handshake, error
checking
and decoding is left mostly for the student.

The project currently supports:

* `TLS_CHACHA20_POLY1305_SHA25` Cipher Suite
* Key exchange with `X25519` and signatures with EdDSA (Elliptic Curve Diffie-Hellman key exchange using Curve25519 and
  Edwards-Curve Digital Signature Algorithm based on the same curve)

## Quickstart for Rust

We do not provide teaching for the language itself, but we can help on many issues.
If you have programmed with any low-level language, you should be able to grasp the basics quickly, if the Rust is still
unknown.

If you fight with the compiler, it is just preventing potential bugs from the runtime instead.
You have to adopt the idea that data is always owned.
Read the chapter in Rust's book about [ownership.](https://doc.rust-lang.org/book/ch04-00-understanding-ownership.html)

This project attempts to avoid some complex features of Rust.
You don't need to know lifetimes to complete the TLS handshake and decrypt application data content. It is okay to make
additional copying on this project
with the cost of performance and increased memory usage.

For general guidance, check

* [The Rust Book](https://doc.rust-lang.org/book/)
* You can use ChatGPT, Copilot, or other LLM, for example, to explain some complex lines of code. They are usually very
  accurate.

To get started with Rust environment, use [Rustup.](https://www.rust-lang.org/tools/install)

It is also important to get your IDE environment properly set up. For a beginner, the most straight-forward ways are:

* Use VSCode with [Rust Analyzer](https://code.visualstudio.com/docs/languages/rust).
    * Configure
      VSCode [to run `rustfmt` on save](https://stackoverflow.com/questions/67859926/how-to-run-cargo-fmt-on-save-in-vscode).
    * After that, the editor should be able to note most problems in the code, and for example, to run single functional
      tests from the IDE.
    * You can also use [Clippy](https://doc.rust-lang.org/nightly/clippy/usage.html) to find issues in your code. You
      can also configure VSCode to run it automatically in real-time, but it will take some resources.
    * Additionally, if you want to try, you can also use a student license to run GitHub Copilot. But don't adapt code
      pieces you don't understand. It also gives access to
      using [GitHub Copilot Chat with your code](https://docs.github.com/en/copilot/github-copilot-chat/about-github-copilot-chat).
      After that, you can even highlight specific code and ask questions or suggestions from the Copilot. But then
      again, do not use things blindly. However, *it is extremely useful for this project, since we write some
      repetitive code*.
* Use the student license for [JetBrains RustRover.](https://www.jetbrains.com/rust/)
    * You can apply the same as above also for RustRover.

## Usage

The program takes a single argument as a parameter.
You can use the `RUST_LOG` environment variable to change the logging level. (one of `debug`, `info`, `warn`, `error`)

To run with debug level and install dependencies, just

```shell
RUST_LOG=info cargo run cloudflare.com:443
```

This will do a partial TLS 1.3 handshake with cloudflare.com

## What works?

It is very helpful to look at the process flow [here](https://tls13.xargs.org) to understand what is the current status.

The project implements the necessary data structures and cryptographic primitives to create the initial `ClientHello`
message and convert it into raw bytes with correct length determinants.

It also implements minimal data structures and decoders to parse the first TLS Record from the server response, which
includes the `ServerHello` message.

As a result, the following output log can be seen:

```prolog
RUST_LOG=info cargo run cloudflare.com:443
    Finished dev [unoptimized + debuginfo] target(s) in 0.14s
     Running `target/debug/tls13tutorial 'cloudflare.com:443'`
[2024-03-29T11:27:53Z INFO  tls13tutorial] Successfully connected to the server 'cloudflare.com:443'.
[2024-03-29T11:27:53Z INFO  tls13tutorial] The handshake request has been sent...
[2024-03-29T11:27:53Z INFO  tls13tutorial] Response TLS Record received!
[2024-03-29T11:27:53Z INFO  tls13tutorial] ServerHello message received: ServerHello { legacy_version: 771, random: [226, 253, 128, 13, 165, 143, 153, 128, 84, 112, 255, 66, 14, 115, 40, 43, 51, 192, 6, 203, 183, 194, 31, 181, 89, 196, 158, 49, 236, 101, 213, 244], legacy_session_id_echo: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31], cipher_suite: [19, 3], legacy_compression_method: 0, extensions: [Extension { extension_type: KeyShare, extension_data: [0, 29, 0, 32, 46, 95, 194, 53, 33, 72, 185, 229, 227, 24, 121, 10, 142, 80, 231, 145, 220, 83, 25, 28, 42, 115, 52, 59, 6, 110, 104, 20, 93, 93, 129, 114] }, Extension { extension_type: SupportedVersions, extension_data: [3, 4] }] }
[2024-03-29T11:27:53Z INFO  tls13tutorial] Response TLS Record received!
[2024-03-29T11:27:53Z ERROR tls13tutorial] Unexpected response type: ChangeCipherSpec
[2024-03-29T11:27:53Z INFO  tls13tutorial] Response TLS Record received!
[2024-03-29T11:27:53Z ERROR tls13tutorial] Unexpected response type: ApplicationData
[2024-03-29T11:27:53Z INFO  tls13tutorial] Response TLS Record received!
[2024-03-29T11:27:53Z ERROR tls13tutorial] Unexpected response type: ApplicationData
```

Since the server gets all the required information from the initial `ServerHello` request, it can start sending encrypted `ApplicationData`, which contains encrypted extensions and certificates. 

The first steps in completing the handshake would decode and decrypt those blocks. 

## Type-Length-Value (TLV) pattern

In (binary) network communication
protocols, [type-length-value or tag-length-value (TLV)](https://en.wikipedia.org/wiki/Type%E2%80%93length%E2%80%93value)
is
a common pattern, and TLS follows it in its many sub-protocols.

For example, the lowest layer in the TLS protocol uses the
so-called [Record Protocol](https://datatracker.ietf.org/doc/html/rfc8446#section-5).

It wraps the higher-level protocols, by following the idea of TLV.
To see that in practice, we can take a look at the TLS Record [ASN.1 definition](https://datatracker.ietf.org/doc/html/rfc8446#appendix-B.1) and `TLSPlaintext` as an example for Rust data structure:

```rust
pub type ProtocolVersion = u16;

#[derive(Debug, Copy, Clone)]
pub enum ContentType {
    Invalid = 0,
    ChangeCipherSpec = 20,
    Alert = 21,
    Handshake = 22,
    ApplicationData = 23,
}

#[derive(Debug, Clone)]
pub struct TLSPlaintext {
    pub record_type: ContentType,
    pub legacy_record_version: ProtocolVersion,
    // 2 bytes to represent
    // always 0x0303 for TLS 1.3, except for the first ClientHello where it can be 0x0301
    pub length: u16,
    // length defined as 2 bytes
    pub fragment: Vec<u8>, // fragment of size 'length'
}
```

In the context of binary encoding, everything must have a size.
The data should be possible to deserialize to the original structure based on the byte stream only.
If we want to serialize the structure of `TLSPlaintext` into bytes, we go in order every field and create the byte
presentation.

* A record field takes 1 byte to present as the max value for `ContentType` is defined to be 255 (`u8`). In this case, the
  type defines the data content of
  the `fragment` field. When you decode the byte stream, you know that the first byte is about `ContentType` and takes
  one byte.
* `ProtocolVersion` has type `u16` and that takes 2 bytes to present this number. On the lower level, we differ a bit from
  basic TLV as the version must be defined early.
* The length of the `fragment` is presented with 2 bytes. Here it has a separate field, but that is not always the case and
  byte arrays with dynamic size should have always a length determinant.
* `fragment` is an array of bytes with a size `length` based on the length of the previous.

TLS Record protocol has the plaintext version and ciphertext version. On the previous, we see the plaintext version.

## Basics of implementing the decoders

The base project reads all the data from the TCP stream
into the [VecDeque](https://doc.rust-lang.org/std/collections/struct.VecDeque.html) buffer.
It might not be the most efficient way to parse bytes, but it allows taking chunks or single bytes without the need to move or
clone the remaining data in the memory.
From a learning point of view, it can be better than parsing traditional vectors or byte slices.

It provides methods such as `drain` or `pop_front` to consume parts from the buffer in the correct order.
This is useful, for example, if we want to implement a decoder for specific type. We consume as many bytes as needed to
construct the object, and the leftover data is still in the original buffer, waiting to construct the follow-up object.

You can try to parse raw byte slices, but be warned about bugs! `VecDeque` can also panic with incorrect index usage.

> [!Note]
> There is already an abraction for `VecDeque` to reduce the repetition of code in [parser.rs](src/parser.rs). You are free to improve this further. There can be bugs already.

## Functional testing (positive and negative)

Implementing functional tests in Rust can be
done [to the same file as implementation](https://doc.rust-lang.org/book/ch11-01-writing-tests.html).

This can be greatly beneficial; it is very easy to implement testing for your structs and their function implementations
without ever needing to run the functionality through the main function in the development phase.

To demonstrate testing, the alert protocol is the simplest sub-protocol in TLS.
Take a look for [alert.rs](src/alert.rs) which implements the data structures and encoders and decoders. At the end of
the file, there is a test module.
If you have configured your IDE correctly, you should be able to click the play ▶
button to run the single test function, for example, `test_alert_from_bytes`, or all the tests from the module at once.

You can also do the same from the command line:

```shell
cargo test alert::tests::test_alert_from_bytes
```

Since the alert protocol uses only two bytes, it is straightforward to implement both positive tests and negative tests.

If you wonder what the `impl std::fmt::Display for` means in the `Alert` data structures, it
implements [a textual presentation for those objects](https://doc.rust-lang.org/rust-by-example/hello/print/print_display.html),
for example, what is the output format when the `println!()` macro is used for the data type.

## Fuzzing the project

If you are using a Linux machine for development, starting fuzz testing with precise control is very straightforward.
There are many fuzzing libraries, that can be integrated to the project to get coverage-guided fuzzing.

Fuzzing provides the stream of bytes for the interface you choose, and depending on the used backend, it will provide
testing data and coverage-guided mutation to test the robustness of the selected functionality.

* [libfuzzer](https://github.com/rust-fuzz/libfuzzer)
* [libAFL](https://github.com/AFLplusplus/LibAFL)

In [fuzzing directory](fuzzing), `libfuzzer` is pre-configured.
You need to use a Linux environment for that.