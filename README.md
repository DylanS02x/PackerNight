# PackerNight
<br>
PackerNight est un projet Rust pour le chiffrement et le déchiffrement de fichiers en utilisant l'algorithme AES-256 en mode CBC, avec compression des données à l'aide de zlib.  
<br>
## Installation
<br>
1. Assurez-vous d'avoir installé [Rust](https://www.rust-lang.org/fr/learn/get-started).
2. Clonez ce dépôt :
```
git clone https://github.com/votre-utilisateur/packernight.git
cd packernight
```
3. Compilez le projet :
```
cargo build --release
```
<br>
## Utilisation
<br>
Pour exécuter le programme, utilisez la commande suivante :
```
cargo run -- <action> <original_file> [encrypted_file]
```
<br>
## Paramètres
<br>
- `<action>` : L'action à effectuer. Les valeurs possibles sont encrypt ou decrypt.
- `<original_file>` : Le chemin vers le fichier original ou chiffré.
- `[encrypted_file]` : Le chemin vers le fichier de sortie chiffré (optionnel pour l'action decrypt).
<br>
## Exemples
<br>
Pour chiffrer un fichier :
```
cargo run -- encrypt example_original example_encrypted
```
Pour déchiffrer un fichier :
```
cargo run -- decrypt example_encrypted
```
<br>
## Fonctionnalités
<br>
- Chiffrement de fichiers en utilisant AES-256 en mode CBC.
- Compression des données avant le chiffrement.
- Décompression et déchiffrement des fichiers.
- Affichage des sections ELF des fichiers en utilisant `readelf`.
- Calcul et affichage des hashs SHA-256 des fichiers avant et après chiffrement/déchiffrement.
- Modification des permissions des fichiers déchiffrés pour les rendre exécutables.
<br>
## Tests
<br>
Pour exécuter les tests unitaires, utilisez la commande suivante :
```
cargo test
```
