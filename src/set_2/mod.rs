#![allow(dead_code)]

mod tests;

use std::{
    collections::{HashMap, HashSet},
    fs,
    io::{self, stdout, Read, Stdout, Write},
    iter, thread,
    time::Duration,
};

use aes::{
    cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit},
    Aes128,
};
use base64::{engine::general_purpose, Engine};
use rand::prelude::*;

use crate::set_1::{decrypt_aes_ecb, fixed_xor};

#[derive(PartialEq, Debug)]
enum EncryptionType {
    Ecb,
    Cbc,
}

pub fn pkcs7_padding(plain_text: &[u8], block_size: usize) -> Vec<u8> {
    let diff = block_size - (plain_text.len() % block_size);
    let padding: Vec<u8> = iter::repeat(diff as u8).take(diff).collect();
    let mut v = plain_text.to_vec();
    v.extend(padding);
    v
}

fn cbc_encryption(key_stream: &[u8], plain_text: &[u8], init_vector: &[u8]) -> Vec<u8> {
    let mut cipher = Vec::new();
    let init_vector = init_vector.to_vec();

    let padded = pkcs7_padding(plain_text, 16);

    padded.chunks(16).for_each(|chunk| {
        let last_cipher = cipher.last().unwrap_or(&init_vector);

        let xor_res = fixed_xor(last_cipher, chunk);
        let encrypted = encrypt_aes_ecb(key_stream, &xor_res);

        cipher.push(encrypted);
    });

    cipher.into_iter().flatten().collect()
}

fn cbc_decryption(key_stream: &[u8], cipher: &[u8], init_vector: &[u8]) -> Vec<u8> {
    let mut res = Vec::new();

    let chunked: Vec<&[u8]> = cipher.chunks(16).collect();

    chunked
        .iter()
        .enumerate()
        .for_each(|(index, cipher_chunk)| {
            let last = if index == 0 {
                init_vector
            } else {
                chunked[index - 1]
            };

            let decrypted = decrypt_aes_ecb(key_stream, cipher_chunk);

            let xor = fixed_xor(&decrypted, last);
            res.push(xor);
        });

    let padding_len = *res.last().unwrap().last().unwrap() as usize;
    res.into_iter()
        .flatten()
        .take(cipher.len() - padding_len)
        .collect()
}

pub fn encrypt_aes_ecb(key_stream: &[u8], plain_text: &[u8]) -> Vec<u8> {
    let cipher = Aes128::new(GenericArray::from_slice(key_stream));

    let mut v: Vec<_> = plain_text
        .chunks(16)
        .map(GenericArray::clone_from_slice)
        .collect();

    cipher.encrypt_blocks(&mut v);
    v.into_iter().flatten().collect()
}

fn generate_random_aes_key() -> [u8; 16] {
    let mut rng = rand::thread_rng();
    let r: [u8; 16] = rng.gen();

    r
}

fn encryption_oracle(plain_text: &[u8]) -> (Vec<u8>, EncryptionType) {
    let key = generate_random_aes_key();
    let mut rng = SmallRng::from_rng(thread_rng()).unwrap();
    let pad_size = rng.gen_range(5..=10);
    let mut before: [u8; 10] = [0; 10];
    let mut after: [u8; 10] = [0; 10];
    rng.fill_bytes(&mut before);
    rng.fill_bytes(&mut after);

    let res = [&before[..pad_size], plain_text, &after[..pad_size]].concat();

    let padded = pkcs7_padding(&res, 16);
    if rng.gen() {
        // encrypt with ecb
        let res = encrypt_aes_ecb(&key, &padded);
        (res, EncryptionType::Ecb)
    } else {
        // encrypt with cbc
        let mut init_vec = [0u8; 16];
        rng.fill_bytes(&mut init_vec);
        let res = cbc_encryption(&key, &padded, &init_vec);
        (res, EncryptionType::Cbc)
    }
}

fn detect_block_cipher_mode(cipher: &[u8]) -> EncryptionType {
    if is_ecb(cipher) {
        EncryptionType::Ecb
    } else {
        EncryptionType::Cbc
    }
}

fn is_ecb(cipher: &[u8]) -> bool {
    let chunked: Vec<_> = cipher.chunks(16).collect();
    let set: HashSet<_> = HashSet::from_iter(&chunked);

    chunked.len() != set.len()
}

fn byte_at_a_time_ecb_detection() -> String {
    let mut key = [0u8; 16];
    let mut rng = SmallRng::from_rng(thread_rng()).unwrap();
    rng.fill_bytes(&mut key);

    let (cipher_len, block_size) = get_block_size(&key);
    let blocks = cipher_len / block_size;

    if is_ecb(&ecb_oracle(&key, &vec![0; block_size * block_size])) {
        let mut plain_text = vec![];
        for block in 0 .. blocks {
          for i in 1..= block_size {
              let f = build_codebook(block_size, &key, &plain_text);
              let b = vec![0; block_size - i];
              let start = block * block_size;
              let end = start + block_size;

              let oracle_res = ecb_oracle(&key, &b);
              let s: String = oracle_res[start .. end]
                  .iter()
                  .map(|b| *b as char)
                  .collect();

              if let Some(res) = f.get(&s) {
                  plain_text.push(*res);
                  // print!("{}", *res as char);
                  // io::stdout().flush().unwrap();
              }
          }
        }
        let s = String::from_utf8(plain_text).unwrap();
        println!("{}", &s);
        s
    } else {
        "Not ECB".to_string()
    }
}

fn get_block_size(key: &[u8]) -> (usize, usize) {
    let init = [0u8; 1];
    let initial_len = ecb_oracle(key, &init).len();

    let mut block_size = 0;
    for i in 2..=100 {
        let s = vec![0; i];
        let cipher_len = ecb_oracle(key, &s).len();

        block_size = cipher_len - initial_len;

        if block_size != 0 {
            break;
        }
    }

    println!("Block Size: {}\nInitial len: {}\n\n", block_size, initial_len);

    (initial_len, block_size)
}

fn ecb_oracle(key: &[u8], plain_text: &[u8]) -> Vec<u8> {
    let s = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";
    let decoded = general_purpose::STANDARD.decode(s).unwrap();
    let plain_text = [plain_text, &decoded].concat();
    let padded = pkcs7_padding(&plain_text, 16);
    encrypt_aes_ecb(key, &padded)
}

fn build_codebook(block_size: usize, key: &[u8], plain_text: &[u8]) -> HashMap<String, u8> {
    let mut map = HashMap::new();
    let p = vec![0u8; block_size];
    let p = [&p, plain_text, &[0u8]].concat();
    let mut p = p[p.len() - block_size..].to_vec();

    for i in 0u8..=255 {
        p[block_size - 1] = i;
        let oracle_res = ecb_oracle(key, &p);
        let s: String = oracle_res
            .into_iter()
            .take(block_size)
            .map(|b| b as char)
            .collect();
        map.insert(s, i);
    }

    map
}


