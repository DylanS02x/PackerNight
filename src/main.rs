mod encrypt;
mod decrypt;

// Importation du trait Parser de la crate clap
use clap::Parser;
use std::error::Error;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};

#[derive(Parser)]
#[command(name = "...")]
#[command(about = "...", long_about = None)]
struct Cli {
    /// L'action à effectuer : 'encrypt' ou 'decrypt'
    action: String,

    /// Le fichier original ou chiffré
    original_file: String,

    /// Le fichier de sortie chiffré (optionnel pour l'action decrypt)
    encrypted_file: Option<String>,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Cli::parse();

    // Codes d'échappement ANSI pour les couleurs
    let red = "\x1b[31m";
    let green = "\x1b[32m";
    let blue = "\x1b[34m";
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
                encrypt::encrypt_file(&args.original_file, encrypted_file)?;
                println!("{}[-] Le fichier '{}' a été chiffré avec succès !{}", green, args.original_file, reset);
                println!("{}[-] Nom du fichier de sortie : {}{}", blue , encrypted_file, reset);
            } else {
                eprintln!("{}[x] Erreur : Les fichiers d'entrée et de sortie doivent être spécifiés pour l'action 'encrypt'.{}", red, reset);
                std::process::exit(1);
            }
        },
        "decrypt" => {
            println!("[-] Déchiffrement en cours...");
            decrypt::decrypt_and_decompress_file(&args.original_file, &args.original_file)?;
            println!("{}[-] Le fichier '{}' a été déchiffré avec succès !{}", green, args.original_file, reset);

            // Afficher les permissions actuelles
            let metadata = fs::metadata(&args.original_file)?;
            let current_permissions = metadata.permissions().mode();
            println!("[-] Permissions actuelles du fichier : {:o}", current_permissions);

            // Accorder les permissions d'exécution au fichier déchiffré
            println!("[-] Attribution des permissions d'exécution au fichier déchiffré...");
            let mut perms = metadata.permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&args.original_file, perms)?;

            // Vérifier les nouvelles permissions
            let new_permissions = fs::metadata(&args.original_file)?.permissions().mode();
            println!("[-] Nouvelles permissions du fichier : {:o}", new_permissions);

            // Vérifier l'existence du fichier juste avant l'exécution
            if !fs::metadata(&args.original_file).is_ok() {
                eprintln!("{}[x] Erreur : Le fichier '{}' n'existe pas avant l'exécution.{}", red, args.original_file, reset);
                std::process::exit(1);
            }

            // Afficher le chemin absolu du fichier
            let abs_path = fs::canonicalize(&args.original_file)?;
            println!("[-] Chemin absolu du fichier à exécuter : {:?}", abs_path);

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