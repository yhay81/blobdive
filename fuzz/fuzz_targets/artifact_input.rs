#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = blobdive::detect::detect(data);
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = blobdive::reference::parse_reference(text);
    }
});
