#[cfg(test)]
pub mod set_3_tests {
    use base64::{engine::general_purpose, Engine};
    use std::fs;

    use crate::set_3::{break_fixed_nonce_ctr, use_ctr_mode, MersenneTwisterRNG, PaddingOracle, PaddingOracleAttacker};

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

    #[test]
    fn test_mersenne_twister_rng() {
        let test_values = [
            3521569528u32, 1101990581, 1076301704, 2948418163, 3792022443, 2697495705, 2002445460,
            502890592, 3431775349, 1040222146, 3582980688, 1840389745, 4282906414, 1327318762,
            2089338664, 4131459930, 3027134324, 2835148530, 1179416782, 1849001581, 526320344,
            2422121673, 2517840959, 2221714477, 55000521, 591044015, 1168297933, 1971159042,
            4039967188, 4139787488, 122076017, 2865003221, 2757324559, 1140549535, 244059003,
            4193854726, 18931592, 4249850126, 312057759, 3675685089, 280972886, 1066277295,
            2046947247, 2429544615, 2740628128, 2155829340, 3777224149, 1593303098, 3225103480,
            1218072373, 721749912, 3875531970,
        ];

        let mut rng = MersenneTwisterRNG::new(Some(1131464071));
        for expected in test_values {
          let actual = rng.extract_number();
          assert_eq!(expected, actual)
        }
    }
}
