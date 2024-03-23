# TLS 1.3 protocol implementation in Rust

This is an educational project to learn about the TLS 1.3 protocol and general challenges on implementing binary-level
network protocols.

The project attempts to follow the standard [RFC8466](https://datatracker.ietf.org/doc/html/rfc8446) as closely as
possible in naming conventions and data structures when converting to Rust.

In communication
protocols [type-length-value or tag-length-value (TLV)](https://en.wikipedia.org/wiki/Type%E2%80%93length%E2%80%93value)
is
a common pattern and TLS follows oit.