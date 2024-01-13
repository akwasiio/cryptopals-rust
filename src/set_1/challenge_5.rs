/// Here is the opening stanza of an important work of the English language:
/// 
/// Burning 'em, if you ain't quick and nimble
/// I go crazy when I hear a cymbal
///
/// Encrypt it, under the key "ICE", using repeating-key XOR.
/// 
/// In repeating-key XOR, you'll sequentially apply each byte of the key;
/// the first byte of plaintext will be XOR'd against I, the next C, the next E,
/// then I again for the 4th byte, and so on.
/// 
/// It should come out to:
/// 
/// 0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272
/// a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f
///
/// Encrypt a bunch of stuff using your repeating-key XOR function. Encrypt your mail.
/// Encrypt your password file. Your .sig file.
/// Get a feel for it. I promise, we aren't wasting your time with this.

fn repeating_key_xor() -> String {
    let text_stream = "Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal".as_bytes();
    let key_stream = "ICE".as_bytes();

    let mut i = 0;
    let mut res = vec![];

    for byte in text_stream {
        res.push(byte ^ key_stream[i]);
        i = (i + 1) % key_stream.len(); // modulo div so we can wrap around to first byte
    }

    hex::encode(&res)
}

#[test]
fn test() {
    assert_eq!(repeating_key_xor(), "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f")
}