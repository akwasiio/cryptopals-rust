use std::collections::HashSet;
use std::fs;

fn detect_ecb() -> Option<String> {
    let mut res = None;
    let f = fs::read_to_string("texts/8.txt").unwrap();

    for (i, line) in f.lines().enumerate() {
        let decoded = hex::decode(line).unwrap();
        let chunked: Vec<_> = decoded.chunks(16).collect();
        let set: HashSet<_> = HashSet::from_iter(&chunked);

        if chunked.len() != set.len() {
            // println!("I: {i}");
            // println!("Line: {}", line);
            // println!("Hash len: {}", set.len());
            // println!("chunked_len: {}", chunked.len());
            res = Some(line.to_string());
            break;
        }
    }
    res
}

#[test]
fn test() {
    let expected = "d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a";
    assert_eq!(Some(expected), detect_ecb().as_deref())
}