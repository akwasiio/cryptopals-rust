#![allow(dead_code)]

mod tests;

use std::fs;

use crate::{set_1::{fixed_xor, single_byte_xor}, set_2::encrypt_aes_ecb, utils::{get_english_corpus, transpose}};
use base64::{engine::general_purpose, Engine};
use rand::{thread_rng, Rng};

use crate::set_2::{cbc_decryption, cbc_encryption, has_padding};
use crate::utils::get_uppercase_corpus;

struct PaddingOracle {
    key: [u8; 16],
    iv: [u8; 16],
}

impl PaddingOracle {
    pub fn new() -> Self {
        let mut rng = rand::thread_rng();

        Self {
            key: rng.gen(),
            iv: rng.gen(),
        }
    }

    fn pick_random_plain_text(&self) -> Vec<u8> {
        let mut rng = thread_rng();
        let rand_idx = rng.gen_range(0..10);
        let ciphers = [
            "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
            "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
            "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
            "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
            "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
            "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
            "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
            "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
            "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
            "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
        ];
        let selected_cipher = ciphers[rand_idx];

        general_purpose::STANDARD.decode(selected_cipher).unwrap()
    }

    pub fn encrypt(&self, plain_text: &[u8]) -> Vec<u8> {
        // let plain_text = self.pick_random_plain_text();
        cbc_encryption(&self.key, plain_text, &self.iv)
    }

    pub fn decrypt(&self, cipher: &[u8], iv: &[u8]) -> Option<Vec<u8>> {
        let decrypted = cbc_decryption(&self.key, cipher, iv);
        // println!("Decrypted: {:?}", &s);
        // println!("IV: {:?}", iv);

        if has_padding(&decrypted) {
            return Some(decrypted);
        }
        None
    }
}

struct PaddingOracleAttacker;

impl PaddingOracleAttacker {
    pub fn attack(&self, oracle: &PaddingOracle, c: &[u8]) -> String {
        let v: Vec<Vec<_>> = c
            .chunks(16)
            .map(|chunk| {
                let mut res: Vec<u8> = vec![0u8; 16];
                let mut count = 1;
                let mut padding = [0u8; 16];

                for idx in (0..chunk.len()).rev() {
                    if count >= 2 {
                        for i in idx + 1..chunk.len() {
                            padding[i] = res[i] ^ count
                        }
                    }

                    count += 1;
                    for b in 0x00u8..=0xFF {
                        padding[idx] = b;
                        if let Some(plain_text) = oracle.decrypt(chunk, &padding) {
                            res[idx] = plain_text[idx] ^ b;
                            break;
                        }
                    }
                }

                res
            })
            .collect();
        // println!("final interm: {:?}", interm);
        // println!("final: {:?}", v);

        let mut res = vec![];

        for (index, current) in v.iter().enumerate() {
            let prev = if index == 0 {
                oracle.iv.to_vec()
            } else {
                let start = 16 * (index - 1);
                let end = start + 16;
                c[start..end].to_vec()
            };

            let inner_res = fixed_xor(&prev, current);
            res.push(inner_res)
        }

        let s: String = res.concat().iter().map(|c| *c as char).collect();
        s
    }
}

pub fn use_ctr_mode(key: &[u8], nonce: &[u8], plain_text: &[u8]) -> Vec<u8> {
    let mut keystream = vec![vec![]];


    let res: Vec<Vec<_>> = plain_text
        .chunks(16)
        .zip(0..(plain_text.len() as f32 / 16f32).ceil() as usize)
        .map(|(chunk, counter)| {
            let counter: [u8; 8] = u64::to_le_bytes(counter as u64);
            let comb = [nonce, &counter].concat();
            let enc_res = encrypt_aes_ecb(key, &comb);
            keystream.push(enc_res.clone());

            fixed_xor(&enc_res, chunk)
        })
        .collect();

    res.concat()
}

pub fn break_fixed_nonce_ctr(plain_texts: Vec<Vec<u8>>) -> String {
    // encrypt all lines
    let nonce = [0; 8];
    let mut encrypted_res = vec![];
    let mut rng = thread_rng();
    let key: [u8; 16] = rng.gen();

    for text in plain_texts {
        let res = use_ctr_mode(&key, &nonce, &text);
        encrypted_res.push(res)
    }
    let corpus = get_english_corpus();
    let uppercase_corpus = get_uppercase_corpus();

    // get keysize (max length of lines)
    let max_len = encrypted_res.iter().min_by_key(|x| x.len()).unwrap().len();
    let truncated: Vec<Vec<u8>> = encrypted_res.iter().map(|v| v[..max_len].to_vec()).collect();

    // transpose blocks
    let blocks = transpose(&truncated.concat(), max_len);

    let mut keystream = vec![];

    // get keystream using single byte xor
    blocks.iter().enumerate().for_each(|(index, block)| {
        let xor_res = if index == 0 {
            single_byte_xor(block, &uppercase_corpus)
        } else {
            single_byte_xor(block, &corpus)
        };
        // println!("{}: {}", &xor_res.0, &xor_res.1);
        keystream.push(xor_res.0);
    });

    let mut results = String::new();
    // xor keystream with cipher to get plain text
    for cipher in encrypted_res {
        let res = fixed_xor(&keystream, &cipher);
        results = format!("{}\n{}", results, String::from_utf8(res).unwrap())
    }

    results
}


