use crate::set_1::challenge_5::repeating_key_xor;
use crate::set_1::get_english_corpus;
use crate::set_1::single_byte_xor_cipher::single_byte_xor;

type Key = String;



fn break_repeating_key_xor(bytes: &[u8]) -> Key {
    let mut v: Vec<(usize, f64)> = (2..40).map(|k| {
        let b: Vec<&[u8]> = bytes.chunks(k)
            .take(4)
            .collect();

        let mut s = 0.0;
        for i in 0..b.len() {
            for j in i..b.len() {
                s += hamming_distance(&b[i], &b[j]) as f64
            }
        }
        let avg_distance = (s / (k as f64)) / 6f64;
        (k, avg_distance)
    }).collect::<Vec<(usize, f64)>>();

    v.sort_by(|(_, d1), (_, d2)| d1.partial_cmp(d2).unwrap());
    println!("{:?}", v);

    let key_size = v.first().unwrap().0;

    let blocks = transpose(bytes, key_size);
    let mut res = vec![];
    let corpus = get_english_corpus();

    for i in 0..blocks.len() {
        let sres = single_byte_xor(&blocks[i], &corpus);
        res.push(sres.0);
    }
    let s = repeating_key_xor(&bytes, &res);
    println!("{:?}", String::from_utf8(hex::decode(s).unwrap()));

    String::from_utf8(res).unwrap()
}
// For binary strings a and b the Hamming distance is equal to the number of ones (population count) in a XOR b
pub fn hamming_distance(buffer1: &[u8], buffer2: &[u8]) -> u32 {
    buffer1.iter().zip(buffer2.iter())
        .map(|(x, y)| (x ^ y).count_ones())
        .fold(0, |a, n| a + n)
}

fn transpose(bytes: &[u8], chunk_size: usize) -> Vec<Vec<u8>> {
    let chunked: Vec<&[u8]> = bytes.chunks(chunk_size).map(|x| x).collect();
    let mut blocs = vec![vec![0; chunked.len()]; chunk_size];

    for i in 0..chunked.len() {
        for j in 0..chunked[i].len() {
            blocs[j][i] = chunked[i][j]
        }
    }

    blocs
}


#[cfg(test)]
mod tests {
    use std::fs;
    use base64::Engine;
    use base64::engine::general_purpose;

    use crate::set_1::challenge_5::repeating_key_xor;
    use crate::set_1::challenge_6::{break_repeating_key_xor, hamming_distance, transpose};

    #[test]
    fn test_hamming_distance() {
        assert_eq!(hamming_distance("this is a test".as_bytes(), "wokka wokka!!!".as_bytes()), 37)
    }

    #[test]
    fn test_transpose() {
        let bytes: [u8; 20] = [00, 01, 02, 03, 10, 11, 12, 13, 20, 21, 22, 23, 30, 31, 32, 33, 40, 41, 42, 43];
        let expected = vec![
            vec![00, 10, 20, 30, 40], vec![01, 11, 21, 31, 41],
            vec![02, 12, 22, 32, 42], vec![03, 13, 23, 33, 43],
        ];
        let res = transpose(&bytes, 4);
        assert_eq!(expected, res);
    }

    #[test]
    fn test_break_repeating_key_xor() {
        let text = fs::read_to_string("texts/6.txt").unwrap();
        // println!("{}", text);
        let bytes = general_purpose::STANDARD.decode(text.trim()).unwrap();

        let key = break_repeating_key_xor(&bytes);
        assert_eq!("Terminator X: Bring the noise", key);
    }
}
