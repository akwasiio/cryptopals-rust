use std::fs;
use crate::set_1::create_corpus;
use crate::set_1::fixed_xor::xor;
use crate::set_1::single_byte_xor_cipher::get_score_of_english_chars;

/// One of the 60-character strings in this file has been encrypted by single-character XOR.
//
/// Find it.
fn detect_single_char_xor() -> char {
    let texts = fs::read_to_string("texts/single-char.txt").unwrap();
    let corpus_text = fs::read_to_string("texts/pride-and-prejudice.txt").unwrap();
    let corpus = create_corpus(corpus_text);

    let mut char = ' ';
    let mut best_score = 0.0;

    for i in 0_u8 ..= 255 {
        let k = vec![i; 60];
        for line in texts.lines() {
            let x = hex::decode(line).unwrap();
            let xord = xor(&x, &k);

            if let Ok(value) = String::from_utf8(xord) {
                let score = get_score_of_english_chars(value, &corpus);
                if score > best_score {
                    best_score = score;
                    char = i as char;
                }
            }
        }
    }
    char
}

#[test]
fn test() {
    assert_eq!(detect_single_char_xor(), '5')
}