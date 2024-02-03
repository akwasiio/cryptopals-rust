#![allow(dead_code)]

mod tests;

use std::{collections::HashSet, iter};

use aes::{
    Aes128,
    cipher::{BlockEncrypt, generic_array::GenericArray, KeyInit},
};
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

    let res = [
        &before[..pad_size],
        plain_text,
        &after[..pad_size],
    ]
        .concat();

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
    if is_ecb(&cipher) {
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


