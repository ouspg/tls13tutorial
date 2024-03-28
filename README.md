# TLS 1.3 protocol implementation in Rust

This is an educational project to learn about the TLS 1.3 protocol and general challenges on implementing binary-level
network protocols.

The project attempts to follow the standard [RFC8466](https://datatracker.ietf.org/doc/html/rfc8446) as closely as
possible in naming conventions and data structures when converting the standard into Rust implementation.

The implementation is not likely the most efficient in terms of performance, or might not apply all the best
cryptographic
practices (e.g. constant times).
It leaves cryptographic operations mostly for external libraries, and we just generate some cryptographically random
bits.

In this project, we are more interested in the TLS protocol in byte level and how to implement decoders, create
functional tests for them and integrate fuzzing straight from the beginning.

Most of the data structures and their encoders have been provided. The logic to implement the complete handshake, error
checking
and decoding is left mostly for the student.

## Quickstart for Rust

We do not provide teaching for the language itself, but we can help on many issues.
If you have programmed with any low-level language, you should be able to grasp the basics quickly, if the Rust is still
unknown.

If you fight with the compiler, it is just preventing potential bugs from the runtime instead.
You have to adapt the idea that data is always owned.
Read the chapter in Rust book about [ownership.](https://doc.rust-lang.org/book/ch04-00-understanding-ownership.html)

This project attempts to avoid some complex features of Rust.
You don't need to know lifetimes to complete the TLS handshake and decrypt application data content. It is okay to make
additional copying on this project
with the cost of performance and increased memory usage.

For general guidance, check

* [The Rust Book](https://doc.rust-lang.org/book/)
* You can use ChatGPT, Copilot, or other LLM, for example, to explain some complex lines of code. They are usually very
  accurate.

To get started with Rust environment, use [rustup.](https://www.rust-lang.org/tools/install)

It is also important to get your IDE environment properly set up. For a beginner, the most straight-forward ways are:

* Use VSCode with [Rust Analyzer](https://code.visualstudio.com/docs/languages/rust).
    * Configure
      VSCode [to run `rustfmt` on save](https://stackoverflow.com/questions/67859926/how-to-run-cargo-fmt-on-save-in-vscode).
    * After that, editor should be able to note most problems in the code, and for example, to run single functional
      tests from the IDE.
    * You can also use [Clippy](https://doc.rust-lang.org/nightly/clippy/usage.html) to find issues in your code. You
      can also configure VSCode to run it automatically in real-time, but it will take some resources.
    * Additionally, if you want to try, you can also use student license to run GitHub Copilot. But don't adapt code
      pieces you don't understand. It also gives access to
      using [GitHub Copilot Chat with your code](https://docs.github.com/en/copilot/github-copilot-chat/about-github-copilot-chat).
      After that, you can even highlight specific code and ask questions or suggestions from the Copilot. But then
      again, do not use things blindly.
* Use student license for [JetBrain's RustRover.](https://www.jetbrains.com/rust/)
    * You can apply the same as above also for RustRover.

## Type-Length-Value (TLV) pattern

In (binary) network communication
protocols, [type-length-value or tag-length-value (TLV)](https://en.wikipedia.org/wiki/Type%E2%80%93length%E2%80%93value)
is
a common pattern, and TLS follows it in its many sub-protocols.

For example, the lowest layer in TLS protocol uses
so-called [Record Protocol](https://datatracker.ietf.org/doc/html/rfc8446#section-5).

It wraps the higher level protocols, by following the idea of TLV.
To see in practice, we can take a look for the TLS
Record [ASN.1 definitions](https://datatracker.ietf.org/doc/html/rfc8446#appendix-B.1) and `TLSPlaintext` as example for
Rust data structure:

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

* Record field takes 1 byte to present as the max value for `ContentType` is defined to be 255 (`u8`). In this case, the
  type defines the data content of
  the `fragment` field. When you decode the byte stream, you know that the first byte is about `ContentType` and takes
  one byte.
* `ProtocolVersion` has type `u16` and that takes 2 bytes to present this number. On lower level, we differ a bit from
  basic
  TLV as the version must be defined early.
* Length of the `fragment` is presented with 2 bytes. Here it has a separate field, but that is not always the case and
  byte arrays with dynamic size should have always length determinant.
* `fragment` is an array of bytes with size `length` based on the length of previous.

TLS Record protocol has the plaintext version and ciphertext version. On the previous, we see the plaintext version.

## Basics of implementing the decoders

The base project reads all the data from TCP stream
into [VecDeque](https://doc.rust-lang.org/std/collections/struct.VecDeque.html) buffer.
It might not be most efficient way to parse bytes, but it allows taking chunks or single bytes without need to move or
clone the
remaining data in the memory.
From learning point of view, it can be better than parsing traditional vector or byte slice, and without implementing
anything on own.

It provides methods such as `drain` or `pop_front` to consume parts from the buffer in correct order.
This is useful, for example, if we want to implement decoder for specific type. We consume as much bytes as needed to
construct the object, and the leftover data is still in the original buffer, waiting for constructing the follow-up
object.

You can try to parse raw byte slices, but be warned about bugs! `VecDeque` can also panic with incorrect index usage.

## Functional testing (positive and negative)

Implementing functional tests in Rust can be
done [to the same file as implementation](https://doc.rust-lang.org/book/ch11-01-writing-tests.html).

This can be greatly beneficial; it is very easy to implement testing for your structs and their function implementations
without never needing to run the functionality through the main function on development phase.

To demonstrate testing, alert protocol is the simplest sub-protocol in TLS.
Take a look for [alert.rs](src/alert.rs) which implements the data structures and encoders and decoders. In the end of
the file, there is a test module. If you have configured your IDE correctly, you should be able to click the play ▶
button
to run the single test function, for example, `test_alert_from_bytes`, or all the tests from the module at once.

You can also do the same from the command line:

```shell
cargo test alert::tests::test_alert_from_bytes
```

Since the alert protocol uses only two bytes, it is straightforward to implement both positive tests and negative tests.

If you wonder what the `impl std::fmt::Display for` means in the `Alert` data structures, it
implements [a textual presentation for those objects](https://doc.rust-lang.org/rust-by-example/hello/print/print_display.html),
for example, what is the output format when the `println!()` macro is used for the data type.

## Fuzzing the project

If you are using Linux machine for development, starting fuzz testing with precise control is very straightforward.
There are many fuzzing libraries, which can be integrated to project to get coverage-guided fuzzing.

Fuzzing provides the stream of bytes for the interface you choose, and depending on the used backend, it will provide
testing data and coverage-guided mutation to test robustness of the selected functionality.

* [libfuzzer](https://github.com/rust-fuzz/libfuzzer)
* [libAFL](https://github.com/AFLplusplus/LibAFL)

In [fuzzing directory](fuzzing), `libfuzzer` is pre-configured.
You need to use Linux environment for that.