use goblin::pe::data_directories::DataDirectory;
use goblin::pe::PE;
use goblin::{peek_bytes, Hint};
use scroll::{Pread, Pwrite};
use std::fs::File;
use std::io::prelude::*;
use std::path::Path;
use std::{env, fs};

/// extract code integrity structure and certificate table from a PE binary
fn extract_signature(buf: &[u8]) -> Option<&[u8]> {
    if let Ok(pe) = PE::parse(&buf) {
        // retrieve the IMAGE_OPTIONAL_HEADER if it exists
        if let Some(optional_header) = pe.header.optional_header {
            if let Some(_load_config_hdr) =
                optional_header.data_directories.get_load_config_table()
            {
                if let Some(cert_table_hdr) =
                    optional_header.data_directories.get_certificate_table()
                {
                    let start: usize = cert_table_hdr.virtual_address as usize;
                    let end: usize = (cert_table_hdr.virtual_address
                        + cert_table_hdr.size)
                        as usize;
                    return Some(&buf[start..end]);
                }
            }
        }
    }
    // if PE is not valid or PE does not contain an IMAGE_OPTIONAL_HEADER
    // with a valid certificate table IMAGE_DATA_DIRECTORY entry
    None
}

fn implant_signature(
    buf: &[u8],
    sig: &[u8],
    outfile: &Path,
) -> Result<(), std::io::Error> {
    let pe = PE::parse(&buf).unwrap();
    if let Some(optional_header) = pe.header.optional_header {
        if let Some(_load_config_hdr) =
            optional_header.data_directories.get_load_config_table()
        {
            let mut modified = buf.to_vec();
            // the location of the PE signature is defined by the last 4 bytes
            // of the IMAGE_DOS_HEADER which is at a fixed offset of 0x3c
            let pe_sig_offset = modified.pread::<u32>(0x3c).unwrap();

            // the certificate table data directory entry is located at offset
            // 0x98 (152) bytes from the start of the PE signature for 32-bit or
            // 0xa8 (168) bytes from the start of the PE signature for 64-bit
            let cert_table_offset: u32 =
                pe_sig_offset + if pe.is_64 { 0xa8 } else { 0x98 };

            // use the PWrite trait to write the modified IMAGE_DATA_DIRECTORY
            // entry to the modified binary
            let _result = modified
                .pwrite_with::<DataDirectory>(
                    DataDirectory {
                        virtual_address: buf.len() as u32,
                        size: sig.len() as u32,
                    },
                    cert_table_offset as usize,
                    scroll::LE,
                )
                .unwrap();

            println!("writing modified PE binary...");
            if let Ok(mut write_buf) = File::create(outfile) {
                if write_buf.write_all(&modified).is_ok() {
                    println!(
                        "wrote {} bytes to {}",
                        modified.len(),
                        outfile.display()
                    );
                }
                println!("appending certificate table...");
                if write_buf.write_all(sig).is_ok() {
                    println!(
                        "wrote {} bytes to {}",
                        sig.len(),
                        outfile.display()
                    );
                }
                return Ok(());
            }
        }
    }
    Err(std::io::Error::last_os_error())
}

fn is_pe(file: &str) -> bool {
    if let Ok(mut fp) = File::open(&file) {
        let mut hint: [u8; 16] = [0; 16];
        let _ = fp.read(&mut hint);
        if let Ok(Hint::PE) = peek_bytes(&hint) {
            return true;
        }
    }
    false
}

fn usage() {
    println!(
        "Usage: ./sigtransplant <signed input> <unsigned input> <output>"
    );
}

fn main() {
    let argv: Vec<String> = env::args().collect();
    if argv.len() == 4 && is_pe(&argv[1]) && is_pe(&argv[2]) {
        if let Ok(signed_buf) = fs::read(&argv[1]) {
            if let Some(sig_data) = extract_signature(&signed_buf) {
                if let Ok(unsigned_buf) = fs::read(&argv[2]) {
                    let modified = Path::new(&argv[3]);
                    if implant_signature(&unsigned_buf, &sig_data, &modified)
                        .is_ok()
                        && File::open(&modified).is_ok()
                    {
                        if let Ok(verify) = fs::read(&modified) {
                            extract_signature(&verify);
                        }
                    }
                }
            } else {
                println!(
                    "Input file does not contain an Authenticode signature"
                );
                usage();
            }
        }
    } else {
        usage();
    }
}
