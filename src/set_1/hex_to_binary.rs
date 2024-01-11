use base64::engine::general_purpose;
use base64::Engine;
fn convert_hex_to_base64(hex: &str) -> String {
    let decoded = hex::decode(hex).unwrap();
    general_purpose::STANDARD_NO_PAD.encode(decoded)
}

#[test]
fn test_input() {
    let string = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let results = convert_hex_to_base64(string);

    assert_eq!(
        results,
        "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    )
}
