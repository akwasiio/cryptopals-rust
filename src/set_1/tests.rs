
#[cfg(test)]
mod set1_tests {
    use std::fs;
    use base64::Engine;
    use base64::engine::general_purpose;
    use crate::set_1::*;

    #[test]
    fn test_hex_to_base64() {
        let string = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        let decoded = hex::decode(string).unwrap();

        assert_eq!(
            general_purpose::STANDARD_NO_PAD.encode(decoded),
            "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
        )
    }

    #[test]
    fn test_fixed_xor() {
        let buffer1 = hex::decode("1c0111001f010100061a024b53535009181c").unwrap();
        let buffer2 = hex::decode("686974207468652062756c6c277320657965").unwrap();

        let res = fixed_xor(&buffer1, &buffer2);

        assert_eq!(
            hex::encode(res),
            String::from("746865206b696420646f6e277420706c6179")
        );
    }

    #[test]
    fn test_single_byte_xor() {
        let corpus= get_english_corpus();

        let bytes: Vec<u8> =
            hex::decode("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
                .unwrap();
        assert_eq!(single_byte_xor(&bytes, &corpus).1, "Cooking MC's like a pound of bacon")
    }

    #[test]
    fn test_single_character_xor_detection() {
        assert_eq!(detect_single_char_xor(), '5')
    }

    #[test]
    fn test_repeating_key_xor() {
        let text_stream = "Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal".as_bytes();
        let key_stream = "ICE".as_bytes();
        let res = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
        assert_eq!(repeating_key_xor(text_stream, key_stream), res);
    }

    #[test]
    fn test_breaking_repeating_key_xor() {
        let text = fs::read_to_string("texts/6.txt").unwrap();
        // println!("{}", text);
        let bytes = general_purpose::STANDARD.decode(text.trim()).unwrap();

        let key = break_repeating_key_xor(&bytes);
        assert_eq!("Terminator X: Bring the noise", key);
    }

    #[test]
    fn test_aes_ecb_mode() {
        let f = fs::read_to_string("texts/7.txt")
            .and_then(|s| Ok(s.replace("\n", "")))
            .unwrap();

        let bytes = base64::engine::general_purpose::STANDARD_NO_PAD.decode(f).unwrap();
        let key_stream = "YELLOW SUBMARINE".as_bytes();

        let expected: String = fs::read_to_string("texts/7-answer.txt").unwrap();
        let actual = decrypt_aes_ecb(key_stream, &bytes);

        expected.lines().zip(actual.lines())
            .for_each(|(e, a)| assert_eq!(e.trim(), a.trim()));
    }

    #[test]
    fn test_ecb_detection() {
        let expected = "d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a";
        assert_eq!(Some(expected), detect_ecb().as_deref())
    }
}