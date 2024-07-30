# PackerNight
PackerNight est un projet Rust pour le chiffrement et le déchiffrement de fichiers en utilisant l'algorithme AES-256 en mode CBC, avec compression des données à l'aide de zlib.

## Installation
1 - Assurez-vous d'avoir installé [Rust](https://www.rust-lang.org/fr/learn/get-started).

2 - Clonez ce dépôt :
```
git clone https://github.com/votre-utilisateur/packernight.git
cd packernight/
```
3 - Compilez le projet :
```
cargo build --release
```
## Usage
Pour exécuter le programme, utilisez la commande suivante :
```
cargo run -- <action> <original_file> [encrypted_file]
```
## Paramètres
- `<action>` : L'action à effectuer. Les valeurs possibles sont encrypt ou decrypt.
- `<original_file>` : Le chemin vers le fichier original ou chiffré.
- `[encrypted_file]` : Le chemin vers le fichier de sortie chiffré (optionnel pour l'action decrypt).
## Exemples
Pour chiffrer un fichier :
```
cargo run -- encrypt example_original example_encrypted
```
Pour déchiffrer un fichier :
```
cargo run -- decrypt example_encrypted
```
## Fonctionnalités
- Chiffrement de fichiers en utilisant AES-256 en mode CBC.
- Compression des données avant le chiffrement.
- Décompression et déchiffrement des fichiers.
- Affichage des sections ELF des fichiers en utilisant `readelf`.
- Calcul et affichage des hashs SHA-256 des fichiers avant et après chiffrement/déchiffrement.
- Modification des permissions des fichiers déchiffrés pour les rendre exécutables.
## Tests
Pour exécuter les tests unitaires, utilisez la commande suivante :
```
cargo test
```
