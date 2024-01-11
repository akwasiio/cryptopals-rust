use std::collections::HashMap;
use std::fs;

use crate::set_1::fixed_xor::xor;

/// The hex encoded string:
///
/// 1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736
/// ... has been XOR'd against a single character. Find the key, decrypt the message.
///
/// You can do this by hand. But don't: write code to do it for you.
///
/// How? Devise some method for "scoring" a piece of English plaintext.
/// Character frequency is a good metric. Evaluate each output and choose the one with the best score.

// take a brute force approach? how about we xor the byte string against every alphabet
fn brute(cipher: Vec<u8>) {
    for (char) in 0u8..=255 {
        let bytes = vec![char; cipher.len()];

        let xord = xor(&cipher, &bytes);
        println!("{}", String::from_utf8(xord).unwrap())
    }
}

fn solution() -> String {
    let bytes: Vec<u8> =
        hex::decode("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
            .unwrap();
    let texts = fs::read_to_string("texts/pride-and-prejudice.txt").unwrap();
    let corpus = create_corpus(texts);

    // evaluate each output and choose the one with the best score (has the highest frequency of english chars)
    let mut best_score = 0.0;
    let mut best_xor_res = String::new();

    for i in 0u8..=255 {
        let key_bytes = vec![i; bytes.len()];
        let xor_res = xor(&bytes, &key_bytes);

        match String::from_utf8(xor_res) {
            Ok(value) => {
                let score = get_score_of_english_chars(value.clone(), &corpus);
                if score > best_score {
                    best_score = score;
                    best_xor_res = value;
                }
            }
            Err(_) => {}
        }
    }

    best_xor_res
}

fn get_score_of_english_chars(text: String, corpus: &HashMap<char, f64>) -> f64 {
    let mut score = 0.0f64;
    for c in text.chars() {
        if let Some(freq) = corpus.get(&c) {
            score += freq
        }
    }

    return score / text.chars().count() as f64;
}

fn create_corpus(text: String) -> HashMap<char, f64> {
    let mut corpus_map = HashMap::new();
    for c in text.chars() {
        *corpus_map.entry(c).or_insert(0f64) += 1f64;
    }

    let total = text.chars().count();
    for val in corpus_map.values_mut() {
        *val = *val / total as f64;
    }
    corpus_map
}

#[test]
fn test() {
    assert_eq!(solution(), "Cooking MC's like a pound of bacon")
}
