extern crate aes;
extern crate block_modes;
extern crate flate2;
extern crate hex_literal;
extern crate nom;

use aes::Aes256;
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use hex_literal::hex;
use std::fs::File;
use std::io::{Read, Write, Result};

type Aes256Cbc = Cbc<Aes256, Pkcs7>;

pub fn encrypt_file(input_path: &str, output_path: &str) -> Result<()> {
    let mut file = File::open(input_path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    let key = hex!("000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f");
    let iv = hex!("000102030405060708090a0b0c0d0e0f");

    let mut compressed_encrypted_sections = Vec::new();

    // Simuler des sections pour l'exemple
    let sections = vec![&buffer[..]];

    for section_data in sections {
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(section_data)?;
        let compressed_data = encoder.finish()?;

        let cipher = Aes256Cbc::new_from_slices(&key, &iv)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        let ciphertext = cipher.encrypt_vec(&compressed_data);
        let encrypted_section_size = ciphertext.len() as u64;

        let mut encrypted_section_size_bytes = [0u8; 8];
        encrypted_section_size_bytes.copy_from_slice(&encrypted_section_size.to_le_bytes());

        compressed_encrypted_sections.extend_from_slice(&encrypted_section_size_bytes);
        compressed_encrypted_sections.extend_from_slice(&ciphertext);
    }

    let mut output_file = File::create(output_path)?;
    output_file.write_all(&compressed_encrypted_sections)?;

    Ok(())
}