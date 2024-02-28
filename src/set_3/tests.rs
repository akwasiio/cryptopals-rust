#[cfg(test)]
pub mod set_3_tests {
    use std::fs;
    use base64::{engine::general_purpose, Engine};

    use crate::set_3::{use_ctr_mode, PaddingOracle, PaddingOracleAttacker, break_fixed_nonce_ctr};

    #[test]
    fn test_padding_oracle_attack() {
        let oracle = PaddingOracle::new();
        let attacker = PaddingOracleAttacker;

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

        let mut encrypted_ciphers = vec![vec![]];
        for cipher in ciphers {
            let decoded = general_purpose::STANDARD.decode(cipher).unwrap();
            let encrypted = oracle.encrypt(&decoded);
            encrypted_ciphers.push(encrypted)
        }

        for v in encrypted_ciphers {
            let line = attacker.attack(&oracle, &v);
            println!("{}", line)
        }
    }

    #[test]
    fn test_ctr_mode() {
        let s = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==";
        let decoded = general_purpose::STANDARD.decode(s).unwrap();
        let nonce: [u8; 8] = [0; 8];
        let key = "YELLOW SUBMARINE".as_bytes();

        // let res = ctr_mode_encryption(&nonce, &decoded);
        let decrypted = use_ctr_mode(key, &nonce, &decoded);
        let s = String::from_utf8(decrypted).unwrap();
        let expected = "Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby";
        assert_eq!(expected, s.trim())
    }

    #[test]
    fn test_break_fixed_nonce_ctr() {
        let text = fs::read_to_string("texts/20.txt").unwrap();
        let mut decoded_res = vec![];
        for line in text.lines() {
            let d = general_purpose::STANDARD.decode(line).unwrap();
            decoded_res.push(d);
        }

        let actual = break_fixed_nonce_ctr(decoded_res);
        assert!(actual.contains("Rakim, check this out, yo "));
    }
}

