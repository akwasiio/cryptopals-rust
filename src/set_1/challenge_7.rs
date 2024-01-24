use std::fs;

use aes::Aes128;
use aes::cipher::{BlockDecrypt, KeyInit};
use aes::cipher::consts::U16;
use aes::cipher::generic_array::GenericArray;
use base64::Engine;

fn challenge_7(key_stream: &[u8], text_stream: &[u8]) -> String {
    let key = GenericArray::from_slice(key_stream);
    let cipher = Aes128::new(&key);

    let mut v: Vec<GenericArray<u8, U16>> = text_stream.chunks(16)
        .map(|x|  GenericArray::clone_from_slice(x) )
        .collect();

    cipher.decrypt_blocks(&mut v);

    let res: Vec<u8> = v.iter().flatten().map(|&x| x).collect();
    // println!("{}", String::from_utf8(res).unwrap());
    String::from_utf8(res).unwrap()
}

#[test]
fn test() {
    let f = fs::read_to_string("texts/7.txt")
        .and_then(|s| Ok(s.replace("\n", "")))
        .unwrap();

    let bytes = base64::engine::general_purpose::STANDARD_NO_PAD.decode(f).unwrap();
    let key_stream = "YELLOW SUBMARINE".as_bytes();

    let expected: String = fs::read_to_string("texts/7-answer.txt").unwrap();
    let actual = challenge_7(key_stream, &bytes);

    expected.lines().zip(actual.lines())
        .for_each(|(e, a)| assert_eq!(e.trim(), a.trim()));
    // assert_eq!(expected, challenge_7(key_stream, &bytes));
}