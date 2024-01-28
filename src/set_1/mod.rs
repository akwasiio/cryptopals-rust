#![allow(dead_code)]

use std::collections::{HashMap, HashSet};
use std::fs;
use aes::Aes128;
use aes::cipher::{BlockDecrypt, KeyInit};
use aes::cipher::consts::U16;
use aes::cipher::generic_array::GenericArray;
use crate::set_1::utils::*;
mod utils;
mod tests;

type Key = String;


pub fn fixed_xor(first: &[u8], second: &[u8]) -> Vec<u8> {
    first.iter().zip(second).map(|(f, s)| f ^ s).collect()
}

pub fn single_byte_xor(bytes: &[u8], corpus: &HashMap<char,  f64>) -> (u8, String) {

    // evaluate each output and choose the one with the best score (has the highest frequency of english chars)
    let mut best_score = 0.0;
    let mut best_xor_res = String::new();
    let mut best_key: u8 = 0;

    for i in 0u8..=255 {
        let key_bytes = vec![i; bytes.len()];
        let xor_res = fixed_xor(bytes, &key_bytes);

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


/// One of the 60-character strings in this file has been encrypted by single-character XOR.
//
/// Find it.
pub fn detect_single_char_xor() -> char {
    let texts = fs::read_to_string("texts/single-char.txt").unwrap();
    let corpus = get_english_corpus();

    let mut char = ' ';
    let mut best_score = 0.0;

    for i in 0_u8 ..= 255 {
        let k = vec![i; 60];
        for line in texts.lines() {
            let x = hex::decode(line).unwrap();
            let xord = fixed_xor(&x, &k);

            if let Ok(value) = String::from_utf8(xord) {
                let score = get_score_of_english_chars(value, &corpus);
                if score > best_score {
                    best_score = score;
                    char = i as char;
                }
            }
        }
    }
    char
}


pub fn repeating_key_xor(cipher: &[u8], key: &[u8]) -> String {
    let mut i = 0;
    let mut res = vec![];

    for byte in cipher {
        res.push(byte ^ key[i]);
        i = (i + 1) % key.len(); // modulo div so we can wrap around to first byte
    }

    hex::encode(&res)
}

pub fn break_repeating_key_xor(bytes: &[u8]) -> Key {
    let mut v: Vec<(usize, f64)> = (2..40).map(|k| {
        let b: Vec<&[u8]> = bytes.chunks(k)
            .take(4)
            .collect();

        let mut s = 0.0;
        for i in 0..b.len() {
            for j in i..b.len() {
                s += hamming_distance(&b[i], &b[j]) as f64
            }
        }
        let avg_distance = (s / (k as f64)) / 6f64;
        (k, avg_distance)
    }).collect::<Vec<(usize, f64)>>();

    v.sort_by(|(_, d1), (_, d2)| d1.partial_cmp(d2).unwrap());
    println!("{:?}", v);

    let key_size = v.first().unwrap().0;

    let blocks = transpose(bytes, key_size);
    let mut res = vec![];
    let corpus = get_english_corpus();

    for i in 0..blocks.len() {
        let sres = single_byte_xor(&blocks[i], &corpus);
        res.push(sres.0);
    }
    let s = repeating_key_xor(&bytes, &res);
    println!("{:?}", String::from_utf8(hex::decode(s).unwrap()));

    String::from_utf8(res).unwrap()
}



pub fn decrypt_aes_ecb(key_stream: &[u8], text_stream: &[u8]) -> String {
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


fn detect_ecb() -> Option<String> {
    let mut res = None;
    let f = fs::read_to_string("texts/8.txt").unwrap();

    for (i, line) in f.lines().enumerate() {
        let decoded = hex::decode(line).unwrap();
        let chunked: Vec<_> = decoded.chunks(16).collect();
        let set: HashSet<_> = HashSet::from_iter(&chunked);

        if chunked.len() != set.len() {
            // println!("I: {i}");
            // println!("Line: {}", line);
            // println!("Hash len: {}", set.len());
            // println!("chunked_len: {}", chunked.len());
            res = Some(line.to_string());
            break;
        }
    }
    res
}