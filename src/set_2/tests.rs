use crate::set_2::{detect_block_cipher_mode, encrypt_aes_ecb, encryption_oracle};

#[cfg(test)]
mod set_2_tests {
    use std::collections::HashMap;
    use std::fs;

    use base64::{engine::general_purpose, Engine};

    use crate::set_1::decrypt_aes_ecb;
    use crate::set_2::{
        byte_at_a_time_ecb_detection, cbc_decryption, ecb_cut_and_paste, has_padding, parser,
        pkcs7_padding, profile_for, strip_padding,
    };

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

        println!(
            "Oracle encryption: {:?}\nDetection Result: {:?}",
            oracle_encryption, detection_res
        );
        assert_eq!(oracle_encryption, detection_res)
    }

    #[test]
    fn test_block_size() {
        assert!(
            byte_at_a_time_ecb_detection().contains("The girlies on standby waving just to say hi")
        )
    }

    #[test]
    fn test_parser() {
        let s = "foo=bar&baz=qux&zap=zazzle";
        let m = HashMap::from([
            ("foo".to_string(), "bar".to_string()),
            ("baz".to_string(), "qux".to_string()),
            ("zap".to_string(), "zazzle".to_string()),
        ]);
        let res = parser(s);

        let mut res_keys: Vec<&String> = res.keys().collect();
        res_keys.sort();
        let mut expected_keys: Vec<&String> = m.keys().collect();
        expected_keys.sort();

        let mut res_vals: Vec<&String> = res.values().collect();
        res_vals.sort();
        let mut expected_vals: Vec<&String> = m.values().collect();
        expected_vals.sort();

        assert_eq!(res_keys, expected_keys);
        assert_eq!(expected_vals, res_vals)
    }

    #[test]
    fn test_profile_for() {
        let expected = "email=foo@bar.com&uid=10&role=user";
        let actual = profile_for("foo@bar.com");
        assert_eq!(expected, actual)
    }

    #[test]
    fn test_is_admin() {
        assert!(ecb_cut_and_paste())
    }

    #[test]
    fn test_has_valid_padding() {
        let s = "ICE ICE BABY\x04\x04\x04\x04";
        assert!(has_padding(s.as_bytes()));

        let s = "ICE ICE BABY\x05\x05\x05\x05";
        assert!(!has_padding(s.as_bytes()));

        let s = "ICE ICE BABY\x01\x02\x03\x04";
        assert!(!has_padding(s.as_bytes()))
    }

    #[test]
    fn test_strip_valid_padding() {
        let s = "ICE ICE BABY\x04\x04\x04\x04";
        let expected = "ICE ICE BABY".as_bytes();

        let actual = strip_padding(s.as_bytes());
        assert_eq!(expected, actual.as_slice())
    }

    #[test]
    #[should_panic]
    fn test_try_strip_invalid_padding() {
        let s = "ICE ICE BABY\x01\x02\x03\x04";
        strip_padding(s.as_bytes());
    }
}
