#![allow(dead_code)]

mod tests;

use std::{
    collections::{HashMap, HashSet},
    iter,
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
        for block in 0..blocks {
            for i in 1..=block_size {
                let f = build_codebook(block_size, &key, &plain_text);
                let b = vec![0; block_size - i];
                let start = block * block_size;
                let end = start + block_size;

                let oracle_res = ecb_oracle(&key, &b);
                let s: String = oracle_res[start..end].iter().map(|b| *b as char).collect();

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

    println!(
        "Block Size: {}\nInitial len: {}\n\n",
        block_size, initial_len
    );

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

fn parser(string: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let s: Vec<&str> = string.split(|c: char| c.is_ascii_punctuation()).collect();

    for i in (0..s.len()).step_by(2) {
        let key = s.get(i).unwrap();
        let v = s.get(i + 1).unwrap();
        map.insert(key.to_string(), v.to_string());
    }

    map
}

fn profile_for(email: &str) -> String {
    if email.contains('=') || email.contains('&') {
        panic!("You want to hack the system!")
    }

    format!("email={}&uid=10&role=user", email)
}

pub(crate) fn ecb_cut_and_paste() -> bool {
    let key = generate_random_aes_key();

    // email=foooo@bar.|com&uid=10&role=|user{padding}
    let email = "foooo@bar.com"; // this will make sure user starts it's own block so we can easily cut it out.

    let user_profile = profile_for(email);
    let padded_user_p = pkcs7_padding(user_profile.as_bytes(), 16);
    let encrypted_user_p = encrypt_aes_ecb(&key, &padded_user_p);
    let first_two_blocks = &encrypted_user_p[..32];

    // admin string has to be it's own block so we have to pad
    let padded_admin_string = String::from_utf8(pkcs7_padding(b"admin", 16)).unwrap();
    let admin_email = format!("foooo@bar.{}", padded_admin_string);

    let admin_prof = profile_for(&admin_email);
    let padded_admin_prof = pkcs7_padding(admin_prof.as_bytes(), 16);
    let encrypted_admin_prof = encrypt_aes_ecb(&key, &padded_admin_prof);

    // grab the second block cos that would have the admin encryption.
    let admin_block = &encrypted_admin_prof[16..32];
    let res = [first_two_blocks, admin_block].concat();

    let s = decrypt_aes_ecb(&key, &res);
    let s = String::from_utf8(s).unwrap();
    let s = s.trim();
    println!(
        "User Profile: {}\nHacked Admin Profile: {}",
        user_profile, &s
    );

    let map = parser(s);
    if let Some(role) = map.get("role") {
        role == "admin"
    } else {
        false
    }
}

fn has_padding(plain_text: &[u8]) -> bool {
    let last_byte = *plain_text.last().unwrap() as usize;
    let mut p: Vec<u8> = plain_text.iter().copied().collect();
    p.reverse();

    for _i in 0..last_byte {
        if (p[0] as usize) == last_byte {
            p.remove(0);
        }
    }

    (p.len() + last_byte) % 16 == 0
}

fn strip_padding(plain_text: &[u8]) -> Vec<u8> {
    if !has_padding(plain_text) {
        panic!("Plain text has invalid PKCS#7 padding applied")
    }

    let last_byte = *plain_text.last().unwrap() as usize;

    plain_text
        .iter()
        .copied()
        .take(plain_text.len() - last_byte)
        .collect()
}

struct CbcEncryptionOracle {
    key: [u8; 16],
    iv: [u8; 16],
}

impl CbcEncryptionOracle {
    pub fn new() -> Self {
        let mut rng = thread_rng();
        CbcEncryptionOracle {
            key: rng.gen(),
            iv: rng.gen(),
        }
    }

    pub fn encrypt(&self, payload: &str) -> Vec<u8> {
        let text = payload.replace([';', '='], "_");

        let s = format!(
            "{}{}{}",
            "comment1=cooking%20MCs;userdata=", text, ";comment2=%20like%20a%20pound%20of%20bacon"
        );

        cbc_encryption(&self.key, s.as_bytes(), &self.iv)
    }
}

struct CbcAttacker;

impl CbcAttacker {
    pub fn make_admin(&self, oracle: &CbcEncryptionOracle) -> Vec<u8> {
        let payload = "AAAAA:admin<true";
        let cipher = oracle.encrypt(payload);
        let mut cipher_blocks: Vec<_> = cipher.chunks(16).map(|chunk| chunk.to_vec()).collect();
        // println!("Cipher blocks before: {:?}", &cipher_blocks);
        let target_block = cipher_blocks.get_mut(1).unwrap();
        println!("Target block before: {:?}", &target_block);
        target_block[5] ^= 1;
        target_block[11] ^= 1;

        cipher_blocks.concat()
    }

    pub fn check_is_admin(&self, oracle: &CbcEncryptionOracle, cipher: &[u8]) -> bool {
        let decrypted = cbc_decryption(&oracle.key, cipher, &oracle.iv);
        let p: String = decrypted.into_iter().map(|c| c as char).collect();

        p.contains(";admin=true;")
    }
}


