use std::collections::HashMap;
use std::fs;

mod fixed_xor;
pub mod hex_to_binary;
mod single_byte_xor_cipher;
mod challenge_4;
mod challenge_5;
mod challenge_6;


pub(crate) fn get_english_corpus() -> HashMap<char, f64> {
    let texts = fs::read_to_string("texts/pride-and-prejudice.txt").unwrap();
    create_corpus(texts)
}

pub fn create_corpus(text: String) -> HashMap<char, f64> {
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