#![allow(dead_code)]

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

#[cfg(test)]
mod set_2_tests {
    use std::fs;

    use base64::{Engine, engine::general_purpose};

    use crate::
    set_2::{cbc_decryption, pkcs7_padding}
    ;
    use crate::set_1::decrypt_aes_ecb;

    use super::{detect_block_cipher_mode, encrypt_aes_ecb, encryption_oracle};

    #[test]
    fn test_pkcs7_padding() {
        let text = "YELLOW SUBMARINE".as_bytes();
        let block_size = 20;

        let res = pkcs7_padding(text, block_size);
        assert_eq!(res.len(), block_size);
    }

    #[test]
    fn test_ecb_decryption_and_encryption() {
        let key_stream = "YELLOW_SUBMARINE".as_bytes();

        let text_stream = "This is some random string I'm generating to test if this thing works. Hopefully it's well padded? Idk man, let's see".as_bytes();
        let padded = pkcs7_padding(text_stream, 16);

        let encrypted = encrypt_aes_ecb(key_stream, &padded);
        let decrypted = decrypt_aes_ecb(key_stream, &encrypted);

        assert_eq!(
            String::from_utf8(decrypted).unwrap(),
            String::from_utf8(padded.to_vec()).unwrap()
        )
    }

    #[test]
    fn test_cbc_mode() {
        let t = fs::read_to_string("texts/10.txt")
            .map(|s| s.replace('\n', ""))
            .unwrap();

        let t_bytes = general_purpose::STANDARD_NO_PAD.decode(t).unwrap();
        let key_stream = "YELLOW SUBMARINE".as_bytes();

        let init_vector = "\x00".repeat(16);
        let init_vector = init_vector.as_bytes();

        let decrypted = cbc_decryption(key_stream, &t_bytes, init_vector);

        let first_line = "I'm back and I'm ringin' the bell".to_string();
        let second_line = "A rockin' on the mike while the fly girls yell".to_string();
        let third_line = "In ecstasy in the back of me".to_string();
        let last_line = "Play that funky music";

        let res = String::from_utf8(decrypted).unwrap();
        let res_lines: Vec<&str> = res.trim().lines().map(|l| l.trim()).collect();

        print!("{}", res);
        assert_eq!(first_line, *res_lines.first().unwrap());
        assert_eq!(second_line, *res_lines.get(1).unwrap());
        assert_eq!(third_line, *res_lines.get(2).unwrap());
        assert_eq!(*res_lines.last().unwrap(), last_line);
    }


    #[test]
    fn test_oracle_detection() {
        let text = "Say -- Play that funky music Say, go white boy, go white boy go
play that funky music Go white boy, go white boy, go
Lay down and boogie and play that funky music till you die.

Play that funky music Come on, Come on, let me hear
Play that funky music Come on, Come on, let me hear
Play that funky music Come on, Come on, let me hear
Play that funky music Come on, Come on, let me hear
Play that funky music Come on, Come on, let me hear
Play that funky music Come on, Come on, let me hear
Play that funky music Come on, Come on, let me hear
Play that funky music white boy you say it, say it
Play that funky music A little louder now
Play that funky music, white boy Come on, Come on, Come on
Play that funky music";
        let (cipher, oracle_encryption) = encryption_oracle(text.as_bytes());
        let detection_res = detect_block_cipher_mode(&cipher);

        println!("Oracle encryption: {:?}\nDetection Result: {:?}", oracle_encryption, detection_res);
        assert_eq!(oracle_encryption, detection_res)
    }
}
