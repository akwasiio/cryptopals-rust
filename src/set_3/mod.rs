#![allow(dead_code)]

mod tests;

use crate::{set_1::fixed_xor, set_2::encrypt_aes_ecb};
use base64::{engine::general_purpose, Engine};
use rand::{thread_rng, Rng};

use crate::set_2::{cbc_decryption, cbc_encryption, has_padding};

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

pub fn ctr_mode_encryption(nonce: &[u8], plain_text: &[u8]) -> Vec<u8> {
    let key = "YELLOW SUBMARINE".as_bytes();
    let mut keystream = vec![vec![]];
    let res: Vec<Vec<_>> = plain_text
        .chunks(16)
        .zip(0..(plain_text.len() / 16))
        .map(|(chunk, counter)| {
            let counter: [u8; 8] = u64::to_le_bytes(counter as u64);
            let comb = [nonce, &counter].concat();
            let enc_res = encrypt_aes_ecb(key, &comb);
            keystream.push(enc_res.clone());

            fixed_xor(&enc_res, chunk)
        })
        .collect();

    println!("Key stream, encryption: {:?}", &keystream);
    res.concat()
}

pub fn ctr_mode_decryption(nonce: &[u8], cipher_text: &[u8]) -> Vec<u8> {
    let key = "YELLOW SUBMARINE".as_bytes();

    let iter = cipher_text.chunks_exact(16);
    let mut count = 0;
    let mut res = vec![vec![]];
    for chunk in iter.clone().into_iter() {
        let counter = u64::to_le_bytes(count as u64);
        let comb = [nonce, &counter].concat();
        let enc_res = encrypt_aes_ecb(key, &comb);
        let xor_res = fixed_xor(chunk, &enc_res);
        println!("Xor Res: {:?}", String::from_utf8(xor_res.clone()).unwrap());
        res.push(xor_res);
        count += 1;
    }

    if !iter.remainder().is_empty() {
        let counter = u64::to_le_bytes(count as u64);
        let comb = [nonce, &counter].concat();
        let enc_res = encrypt_aes_ecb(key, &comb);
        let xor_res = fixed_xor(iter.remainder(), &enc_res);
        println!("Xor Res: {:?}", String::from_utf8(xor_res.clone()).unwrap());
        res.push(xor_res);
    }

    res.concat()
    // println!("Len cipher: {}\nLen output: {}", cipher_text.len(), res.len());
    // println!("Res: {}", res)
}

#[test]
fn test_ctr_mode() {
    let s = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==";
    let decoded = general_purpose::STANDARD.decode(s).unwrap();
    let nonce: [u8; 8] = [0; 8];

    // let res = ctr_mode_encryption(&nonce, &decoded);
    let decrypted = ctr_mode_decryption(&nonce, &decoded);
    let s = String::from_utf8(decrypted).unwrap();
    let expected = "Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby";
    assert_eq!(expected, s.trim())
}
