#![allow(dead_code)]

fn pkcs7_padding(plain_text: &[u8], block_size: usize) -> String {
    let mut s = plain_text.to_vec();
    let diff = block_size - s.len();
    s.resize(block_size, diff as u8);
    String::from_utf8(s).unwrap()
}


#[test]
fn test_pkcs7_padding() {
    let text = "YELLOW SUBMARINE".as_bytes();
    let block_size = 20;

    let res = pkcs7_padding(text, block_size);
    assert_ne!(res.len(), text.len());
    assert_eq!(res.len(), block_size)
}