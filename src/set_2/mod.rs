#![allow(dead_code)]

use aes::{
    cipher::{generic_array::GenericArray, typenum::U16, BlockEncrypt, KeyInit},
    Aes128,
};
use std::iter;

use crate::set_1::{decrypt_aes_ecb, fixed_xor};

pub fn pkcs7_padding(plain_text: &[u8], block_size: usize) -> Vec<u8> {
    let diff = block_size - (plain_text.len() % block_size);
    let padding: Vec<u8> = iter::repeat(diff as u8).take(diff).collect();
    let mut v = plain_text.to_vec();
    v.extend(padding);
    v
}

fn cbc_encryption(key_stream: &[u8], plain_text: &[u8]) -> Vec<u8> {
    let mut cipher = Vec::new();
    let init_vector = "\x00".repeat(16).as_bytes().to_vec();

    let padded = pkcs7_padding(plain_text, 16);

    padded.chunks(16).for_each(|chunk| {
        let last_cipher = cipher.last().unwrap_or(&init_vector);

        let xor_res = fixed_xor(last_cipher, chunk);
        let encrypted = encrypt_aes_cbc(key_stream, &xor_res);

        cipher.push(encrypted);
    });

    cipher.into_iter().flatten().collect()
}

fn cbc_decryption(key_stream: &[u8], cipher: &[u8]) -> Vec<u8> {
    let mut res = Vec::new();
    let init_vector = "\x00".repeat(16);
    let init_vector = init_vector.as_bytes();

    let chunked: Vec<&[u8]> = cipher.chunks(16).collect();

    chunked
        .iter()
      .enumerate()
      .for_each(|(index, cipher_chunk)|{
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
    res.into_iter().flatten().take(cipher.len() - padding_len).collect()
}

pub fn encrypt_aes_cbc(key_stream: &[u8], plain_text: &[u8]) -> Vec<u8> {
    let cipher = Aes128::new(GenericArray::from_slice(key_stream));

    let mut v: Vec<GenericArray<u8, U16>> = plain_text
        .chunks(16)
        .map(GenericArray::clone_from_slice)
        .collect();

    cipher.encrypt_blocks(&mut v);
    v.into_iter().flatten().collect()
}

#[cfg(test)]
mod set_2_tests {
    use std::fs;

    use base64::{engine::general_purpose, Engine};

    use crate::{
        set_1::decrypt_aes_ecb,
        set_2::{cbc_decryption, pkcs7_padding},
    };

    use super::encrypt_aes_cbc;

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

        let encrypted = encrypt_aes_cbc(key_stream, &padded);
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

        let decrypted = cbc_decryption(key_stream, &t_bytes);

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
}
