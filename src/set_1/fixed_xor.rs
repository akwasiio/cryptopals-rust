use base64::Engine;
use base64::engine::general_purpose;

/// Write a function that takes two equal-length buffers and produces their XOR combination.
/// If your function works properly, then when you feed it the string:
/// 1c0111001f010100061a024b53535009181c
/// ... after hex decoding, and when XOR'd against:
/// 686974207468652062756c6c277320657965
/// 746865206b696420646f6e277420706c6179

fn xor(first: Vec<u8>, second: Vec<u8>) -> Vec<u8> {
      first.iter().zip(second)
        .map(|(f, s)| f ^ s)
        .collect()
}

fn solution() -> String {
    let buffer1 = hex::decode("1c0111001f010100061a024b53535009181c").unwrap();
    let buffer2 = hex::decode("686974207468652062756c6c277320657965").unwrap();

    hex::encode(xor(buffer1, buffer2))
}



#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_fixed_xor() {
        assert_eq!(solution(), String::from("746865206b696420646f6e277420706c6179"));
    }
}