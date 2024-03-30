//! Macros for test usage only
// NO NEED TO MODIFY THIS FILE
//
/// A macro for testing encoding/decoding for a generic type which implements `ByteSerializable`
/// Takes a type and an object created from the type, an expected byte array for the encoding result
/// Useful for testing both decoding and encoding
#[macro_export]
macro_rules! round_trip {
    ($typ:ty, $value:expr, $expected:expr) => {{
        let value: $typ = $value;
        let expected: &[u8] = $expected;
        let actual_encoding = $value.as_bytes().unwrap();
        pretty_assertions::assert_eq!(expected, &*actual_encoding);
        // Drop the remainder bytes in this case
        let mut actual_encoding = ByteParser::from(actual_encoding);
        let decoded_value = <$typ>::from_bytes(&mut actual_encoding).unwrap();
        pretty_assertions::assert_eq!(value, *decoded_value);
    }};
}

/// A macro for fuzzing. Decode to struct and test if encoding matches the input bytes in case of error
#[macro_export]
macro_rules! fuzz_round_trip {
    ($typ:ty, $value:expr) => {{
        let backup = $value.clone();
        let mut parser = ByteParser::from($value.to_vec());
        if let Ok(decoded_value) = <$typ>::from_bytes(&mut parser) {
            if let Some(actual_encoding) = decoded_value.as_bytes() {
                assert_eq!(actual_encoding, backup.to_vec());
            }
        }
    }};
}
