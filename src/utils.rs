#![allow(dead_code)]
use std::collections::HashMap;
use std::fs;

pub(crate) fn get_english_corpus() -> HashMap<char, f64> {
    let texts = fs::read_to_string("texts/pride-and-prejudice.txt").unwrap();
    create_corpus(texts)
}
fn create_corpus(text: String) -> HashMap<char, f64> {
    let mut corpus_map = HashMap::new();
    for c in text.chars() {
        *corpus_map.entry(c).or_insert(0f64) += 1f64;
    }

    // for c in text.chars() {
    //     *corpus_map.entry(c.to_uppercase().to_string().parse::<char>().unwrap()).or_insert(0f64) += 1f64;
    // }

    let total = text.chars().count();
    for val in corpus_map.values_mut() {
        *val /= total as f64;
    }
    corpus_map
}

pub fn get_uppercase_corpus() -> HashMap<char, f64> {
    let corpus = get_english_corpus();
    let mut upper_corpus = HashMap::new();
    for (k, v) in corpus {
        if !k.is_uppercase() {
            continue
        }
        *upper_corpus.entry(k).or_insert(0f64) += v;
    }

    upper_corpus
}


pub fn get_score_of_english_chars(text: &str, corpus: &HashMap<char, f64>) -> f64 {
    let mut score = 0.0f64;
    for c in text.chars() {
        if let Some(freq) = corpus.get(&c) {
            score += freq
        }
    }

    score / text.chars().count() as f64
}

// For binary strings a and b the Hamming distance is equal to the number of ones (population count) in a XOR b
pub fn hamming_distance(buffer1: &[u8], buffer2: &[u8]) -> u32 {
    buffer1.iter().zip(buffer2.iter())
        .map(|(x, y)| (x ^ y).count_ones())
        .sum::<u32>()
}

pub fn transpose(bytes: &[u8], chunk_size: usize) -> Vec<Vec<u8>> {
    let chunked: Vec<&[u8]> = bytes.chunks(chunk_size).collect();
    let mut blocs = vec![vec![0; chunked.len()]; chunk_size];

    (0..chunked.len()).for_each(|i| {
        (0..chunked[i].len()).for_each(|j| {
            blocs[j][i] = chunked[i][j]
        });
    });

    blocs
}


#[cfg(test)]
mod utils_test {
    use crate::utils::{hamming_distance, transpose};


    #[test]
    fn test_hamming_distance() {
        assert_eq!(hamming_distance("this is a test".as_bytes(), "wokka wokka!!!".as_bytes()), 37)
    }

    #[test]
    fn test_transpose() {
        let bytes: [u8; 20] = [00, 0x1, 0x2, 0x3, 10, 11, 12, 13, 20, 21, 22, 23, 30, 31, 32, 33, 40, 41, 42, 43];
        let expected = vec![
            vec![00, 10, 20, 30, 40], vec![0x1, 11, 21, 31, 41],
            vec![0x2, 12, 22, 32, 42], vec![0x3, 13, 23, 33, 43],
        ];
        let res = transpose(&bytes, 4);
        assert_eq!(expected, res);
    }
}