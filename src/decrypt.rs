//! # Decrypt Module
//! 
//! Ce module fournit des fonctions pour déchiffrer et décompresser des fichiers en utilisant AES-256 en mode CBC avec padding PKCS7 et décompression Zlib.
//! 
//! Les fonctions de ce module permettent de lire un fichier chiffré, le déchiffrer, le décompresser et sauvegarder le résultat dans un nouveau fichier.

extern crate aes;
extern crate block_modes;
extern crate flate2;
extern crate hex_literal;
extern crate nom;

use aes::Aes256;
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;
use flate2::read::ZlibDecoder;
use hex_literal::hex;
use std::fs::File;
use std::io::{Read, Write, Result};
use std::convert::TryInto;

type Aes256Cbc = Cbc<Aes256, Pkcs7>;

/// Déchiffre et décompresse un fichier en utilisant AES-256 en mode CBC avec padding PKCS7 et décompression Zlib.
///
/// # Arguments
///
/// * `path` - Le chemin du fichier chiffré.
/// * `output_path` - Le chemin où le fichier déchiffré sera sauvegardé.
///
/// # Erreurs
///
/// Cette fonction retournera une erreur si le fichier d'entrée ne peut pas être lu ou si le fichier de sortie ne peut pas être écrit.

pub fn decrypt_and_decompress_file(path: &str, output_path: &str) -> Result<()> {
    let mut file = File::open(path)?;
    let mut encrypted_data = Vec::new();
    file.read_to_end(&mut encrypted_data)?;

    let key = hex!("000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f");
    let iv = hex!("000102030405060708090a0b0c0d0e0f");

    let mut decrypted_data = Vec::new();
    let mut index = 0;

    while index < encrypted_data.len() {
        let encrypted_section_size_bytes: [u8; 8] = encrypted_data[index..index + 8]
            .try_into()
            .expect("Slice with incorrect length");
        let encrypted_section_size = u64::from_le_bytes(encrypted_section_size_bytes) as usize;
        index += 8;

        let encrypted_section = &encrypted_data[index..index + encrypted_section_size];
        index += encrypted_section_size;

        let cipher = Aes256Cbc::new_from_slices(&key, &iv)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        let compressed_data = cipher.decrypt_vec(&encrypted_section)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

        let mut decoder = ZlibDecoder::new(&compressed_data[..]);
        let mut decompressed_section = Vec::new();
        decoder.read_to_end(&mut decompressed_section)?;

        decrypted_data.extend_from_slice(&decompressed_section);
    }

    let mut output_file = File::create(output_path)?;
    output_file.write_all(&decrypted_data)?;

    Ok(())
}