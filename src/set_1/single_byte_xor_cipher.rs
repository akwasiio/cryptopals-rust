use std::collections::HashMap;

use crate::set_1::fixed_xor::xor;
use crate::set_1::get_english_corpus;

/// The hex encoded string:
///
/// 1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736
/// ... has been XOR'd against a single character. Find the key, decrypt the message.
///
/// You can do this by hand. But don't: write code to do it for you.
///
/// How? Devise some method for "scoring" a piece of English plaintext.
/// Character frequency is a good metric. Evaluate each output and choose the one with the best score.

pub fn single_byte_xor(bytes: &[u8], corpus: &HashMap<char,  f64>) -> (u8, String) {

    // evaluate each output and choose the one with the best score (has the highest frequency of english chars)
    let mut best_score = 0.0;
    let mut best_xor_res = String::new();
    let mut best_key: u8 = 0;

    for i in 0u8..=255 {
        let key_bytes = vec![i; bytes.len()];
        let xor_res = xor(bytes, &key_bytes);

        match String::from_utf8(xor_res) {
            Ok(value) => {
                let score = get_score_of_english_chars(value.clone(), &corpus);
                if score > best_score {
                    best_score = score;
                    best_xor_res = value;
                    best_key = i;
                }
            }
            Err(_) => {}
        }
    }

    (best_key, best_xor_res)
}

pub fn get_score_of_english_chars(text: String, corpus: &HashMap<char, f64>) -> f64 {
    let mut score = 0.0f64;
    for c in text.chars() {
        if let Some(freq) = corpus.get(&c) {
            score += freq
        }
    }

    return score / text.chars().count() as f64;
}


#[test]
fn test() {
   let corpus= get_english_corpus();

    let bytes: Vec<u8> =
        hex::decode("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
            .unwrap();
    assert_eq!(single_byte_xor(&bytes, &corpus).1, "Cooking MC's like a pound of bacon")
}
