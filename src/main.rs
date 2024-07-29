// Authors : Quentin Auspitz & Dylan Sandogo
// Project : PackerNight

//! # PackerNight
//!
//! PackerNight est un outil pour chiffrer et déchiffrer des fichiers ELF, en fournissant des
//! fonctionnalités de hachage pour vérifier l'intégrité des fichiers.
//!
//! ## Modules
//!
//! - `encrypt`: Contient les fonctions de chiffrement.
//! - `decrypt`: Contient les fonctions de déchiffrement.
//! - `tests`: Contient les tests unitaires pour vérifier le bon fonctionnement du chiffrement et du déchiffrement.
//! # Argpass
//! 
//! 
//! Ce programme supporte deux actions :
//! 
//! - `encrypt` : Chiffre un fichier spécifié.
//! - `decrypt` : Déchiffre un fichier spécifié et exécute le fichier déchiffré.
//! ## Usage
//!
//! ```shell
//! cargo run -- encrypt <input_file> <output_file>
//! cargo run -- decrypt <input_file> <output_file>
//! ```
//!
//! ## Examples
//!
//! ```rust
//! // Chiffrement d'un fichier
//! encrypt::encrypt_file("example_original", "example_encrypted").unwrap();
//!
//! // Déchiffrement d'un fichier
//! decrypt::decrypt_and_decompress_file("example_encrypted", "example_decrypted").unwrap();
//! ```

mod encrypt;
mod decrypt;

use clap::Parser;
use std::error::Error;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};
use std::io::{self, Read};
use sha2::{Sha256, Digest};

/// Structure représentant les arguments de la ligne de commande.
#[derive(Parser)]
#[command(name = "PackerNight")]
#[command(about = "Outil pour chiffrer et déchiffrer des fichiers ELF", long_about = None)]
struct Cli {
    /// L'action à effectuer : 'encrypt' ou 'decrypt'
    action: String,

    /// Le fichier original ou chiffré
    original_file: String,

    /// Le fichier de sortie chiffré (optionnel pour l'action decrypt)
    encrypted_file: Option<String>,
}

/// Calcule le hash SHA-256 d'un fichier donné.
///
/// # Arguments
///
/// * `file_path` - Le chemin du fichier dont le hash doit être calculé.
///
/// # Returns
///
/// Un `Result` contenant le hash sous forme de chaîne de caractères ou une erreur en cas d'échec.
///
/// # Errors
///
/// Cette fonction retourne une erreur si le fichier ne peut pas être lu ou si le calcul du hash échoue.

fn calculate_sha256(file_path: &str) -> io::Result<String> {
    let mut file = fs::File::open(file_path)?;
    let mut hasher = Sha256::new();
    let mut buffer = Vec::new();

    file.read_to_end(&mut buffer)?;
    hasher.update(buffer);
    let hash = hasher.finalize();

    Ok(format!("{:x}", hash))
}

/// Fonction utilitaire pour exécuter `readelf` et capturer la sortie.
///
/// # Arguments
///
/// * `file_path` - Le chemin du fichier ELF à analyser.
///
/// # Returns
///
/// Un `Result` contenant la sortie de `readelf` ou une erreur en cas d'échec.
///
/// # Errors
///
/// Cette fonction retourne une erreur si l'exécution de `readelf` échoue.
fn readelf_sections(file_path: &str) -> Result<String, Box<dyn Error>> {
    let output = Command::new("readelf")
        .arg("-S")
        .arg(file_path)
        .output()?;

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::Other,
            "Erreur lors de l'exécution de readelf",
        )))
    }
}

/// Fonction principale de l'application.
fn main() -> Result<(), Box<dyn Error>> {
    let args = Cli::parse();

    // Codes d'échappement ANSI pour les couleurs
    let red = "\x1b[31m";
    let green = "\x1b[32m";
    let blue = "\x1b[34m";
    let orange = "\x1b[38;5;208m";
    let reset = "\x1b[0m";

    // Vérifie que le fichier original existe
    if !fs::metadata(&args.original_file).is_ok() {
        eprintln!("{}[x] Erreur : Le fichier original '{}' n'existe pas.{}", red, args.original_file, reset);
        std::process::exit(1);
    }

    // Vérifie que le fichier est bien un fichier
    if !fs::metadata(&args.original_file)?.is_file() {
        eprintln!("{}[x] Erreur : '{}' n'est pas un fichier.{}", red, args.original_file, reset);
        std::process::exit(1);
    }
    
    // Vérifie les valeurs des arguments et appelle les fonctions appropriées
    match args.action.as_str() {
        "encrypt" => {
            if let Some(encrypted_file) = &args.encrypted_file {
                println!("[-] Chiffrement en cours...");

                // Calculer et afficher le hash du fichier original
                let original_hash = calculate_sha256(&args.original_file)?;
                eprintln!("{}[+] Hash avant chiffrement: {} {}", orange, original_hash, reset);

                // Lire les sections du fichier original
                println!("[-] Sections du fichier original :");
                match readelf_sections(&args.original_file) {
                    Ok(sections) => println!("{}", sections),
                    Err(e) => eprintln!("{}[x] Erreur lors de la lecture des sections du fichier original : {}{}", red, e, reset),
                }

                encrypt::encrypt_file(&args.original_file, encrypted_file)?;

                println!("{}[-] Le fichier '{}' a été chiffré avec succès !{}", green, args.original_file, reset);
                println!("{}[-] Nom du fichier de sortie : {}{}", blue, encrypted_file, reset);

                // Lire les sections du fichier chiffré
                println!("[-] Sections du fichier chiffré :");
                match readelf_sections(encrypted_file) {
                    Ok(sections) => println!("{}", sections),
                    Err(_e) => {
                        println!("{}[-] Le fichier chiffré ne peut pas être lu par readelf, ce qui est attendu si le chiffrement est correct.{}", green, reset);
                    },
                }
            } else {
                eprintln!("{}[x] Erreur : Les fichiers d'entrée et de sortie doivent être spécifiés pour l'action 'encrypt'.{}", red, reset);
                std::process::exit(1);
            }
        },
        "decrypt" => {
            println!("[-] Déchiffrement en cours...");
            let decrypted_file = "decrypted_output"; // Nom du fichier de sortie déchiffré
            decrypt::decrypt_and_decompress_file(&args.original_file, decrypted_file)?;

            // Calculer et afficher le hash du fichier déchiffré
            let decrypted_hash = calculate_sha256(decrypted_file)?;
            println!("{} [+] Hash après déchiffrement: {} {}", orange, decrypted_hash, reset);

            println!("{}[-] Le fichier '{}' a été déchiffré avec succès !{}", green, args.original_file, reset);
            println!("{}[-] Nom du fichier de sortie : {}{}", blue, decrypted_file, reset);

            // Afficher les permissions actuelles
            let metadata = fs::metadata(decrypted_file)?;
            let current_permissions = metadata.permissions().mode();
            println!("[-] Permissions actuelles du fichier : {:o}", current_permissions);

            // Accorder les permissions d'exécution au fichier déchiffré
            println!("[-] Attribution des permissions d'exécution au fichier déchiffré...");
            let mut perms = metadata.permissions();
            perms.set_mode(0o755);
            fs::set_permissions(decrypted_file, perms)?;

            // Vérifier les nouvelles permissions
            let new_permissions = fs::metadata(decrypted_file)?.permissions().mode();
            println!("[-] Nouvelles permissions du fichier : {:o}", new_permissions);

            // Vérifier l'existence du fichier juste avant l'exécution
            if !fs::metadata(decrypted_file).is_ok() {
                eprintln!("{}[x] Erreur : Le fichier '{}' n'existe pas avant l'exécution.{}", red, decrypted_file, reset);
                std::process::exit(1);
            }

            // Afficher le chemin absolu du fichier
            let abs_path = fs::canonicalize(decrypted_file)?;
            println!("[-] Chemin absolu du fichier à exécuter : {:?}", abs_path);

            // Lire les sections du fichier déchiffré
            println!("[-] Sections du fichier déchiffré :");
            match readelf_sections(decrypted_file) {
                Ok(sections) => println!("{}", sections),
                Err(e) => eprintln!("{}[x] Erreur lors de la lecture des sections du fichier déchiffré : {}{}", red, e, reset),
            }

            // Exécuter le fichier déchiffré
            println!("[-] Exécution du fichier déchiffré...");
            let output = Command::new(&abs_path)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .output()
                .expect("Erreur lors de l'exécution du fichier déchiffré");

            if output.status.success() {
                println!("{}[-] Le fichier déchiffré s'est exécuté avec succès !{}", green, reset);
                println!("{}[-] Sortie du programme :\n{}{}", blue, String::from_utf8_lossy(&output.stdout), reset);
            } else {
                eprintln!("{}[x] Erreur : Le fichier déchiffré s'est terminé avec une erreur.{}", red, reset);
                eprintln!("{}[x] Erreur standard :\n{}{}", red, String::from_utf8_lossy(&output.stderr), reset);
            }
        },
        _ => {
            eprintln!("{}[x] Action non reconnue. Veuillez spécifier 'encrypt' ou 'decrypt'.{}", red, reset);
            return Ok(());
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// Teste le chiffrement et le déchiffrement en vérifiant que le hash du fichier original
    /// et du fichier déchiffré sont identiques.
    #[test]
    fn test_encrypt_and_decrypt_with_hash() {
        let original_file = "example_original";
        let encrypted_file = "test";
        let decrypted_file = "decrypted_output";

        // Calculer le hash du fichier original
        let original_hash = calculate_sha256(original_file).expect("Échec du calcul du hachage du fichier original");
        println!("Hash avant chiffrement: {}", original_hash);

        // Chiffrer le fichier
        encrypt::encrypt_file(original_file, encrypted_file).expect("Échec du chiffrement du fichier");

        // Déchiffrer le fichier
        decrypt::decrypt_and_decompress_file(encrypted_file, decrypted_file).expect("Échec du déchiffrement du fichier");

        // Calculer le hash du fichier déchiffré
        let decrypted_hash = calculate_sha256(decrypted_file).expect("Échec du calcul du hachage du fichier déchiffré");
        println!("Hash après déchiffrement: {}", decrypted_hash);

        // Vérifier que les hashs sont identiques
        assert_eq!(original_hash, decrypted_hash);

        // Nettoyer les fichiers de test
        fs::remove_file(encrypted_file).expect("Échec de la suppression du fichier chiffré");
        fs::remove_file(decrypted_file).expect("Échec de la suppression du fichier déchiffré");
    }
}
