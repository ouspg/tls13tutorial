#![no_main]

use libfuzzer_sys::fuzz_target;
use tls13tutorial::alert::Alert;
use tls13tutorial::extensions::ByteSerializable;
// use tls13tutorial::fuzz_round_trip; // See macros.rs to fuzz any type as alert below
use tls13tutorial::parser::ByteParser;

fuzz_target!(|data: &[u8]| {
    // code to fuzz goes here
    fuzz_alert(data);
});

fn fuzz_alert(data: &[u8]) {
    // Macro takes type which implements ByteSerializable and the data to fuzz
    // fuzz_round_trip!(Alert, data);
    let backup = data.to_vec();
    let mut parser = ByteParser::from(data);
    if let Ok(decoded_value) = Alert::from_bytes(&mut parser) {
        if let Some(actual_encoding) = decoded_value.as_bytes() {
            assert_eq!(actual_encoding, backup);
        }
    }
}
