
import os
import argparse
import getpass
import tempfile
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAGIC = b"CVLT01"
SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32
CHUNK_SIZE = 1024 * 1024


def derive_key(passphrase, salt):
    kdf = Scrypt(
        salt=salt,
        length=KEY_SIZE,
        n=2**14,
        r=8,
        p=1,
    )
    return kdf.derive(passphrase.encode("utf-8"))


def encrypt_file(source, destination, passphrase):
    source = Path(source)
    destination = Path(destination)

    if source.resolve() == destination.resolve():
        raise ValueError("Source and destination must be different.")

    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key = derive_key(passphrase, salt)
    aes = AESGCM(key)

    # This beginner-friendly version reads each file into memory.
    plaintext = source.read_bytes()
    ciphertext = aes.encrypt(nonce, plaintext, MAGIC + salt)

    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("xb") as output:
        output.write(MAGIC + salt + nonce + ciphertext)

    print(f"Encrypted: {source} -> {destination}")


def decrypt_file(source, destination, passphrase):
    source = Path(source)
    destination = Path(destination)

    if destination.exists():
        raise FileExistsError(
            f"Destination already exists; refusing to overwrite: {destination}"
        )

    data = source.read_bytes()
    header_size = len(MAGIC) + SALT_SIZE + NONCE_SIZE

    if len(data) < header_size + 16 or not data.startswith(MAGIC):
        raise ValueError(f"Invalid or damaged vault file: {source}")

    offset = len(MAGIC)
    salt = data[offset:offset + SALT_SIZE]
    offset += SALT_SIZE
    nonce = data[offset:offset + NONCE_SIZE]
    ciphertext = data[offset + NONCE_SIZE:]

    key = derive_key(passphrase, salt)
    aes = AESGCM(key)

    try:
        plaintext = aes.decrypt(nonce, ciphertext, MAGIC + salt)
    except InvalidTag:
        raise ValueError(
            "Decryption failed: wrong passphrase or file was modified."
        ) from None

    destination.parent.mkdir(parents=True, exist_ok=True)

    # Exclusive creation prevents accidental overwriting of existing files.
    with destination.open("xb") as output:
        output.write(plaintext)

    print(f"Decrypted: {source} -> {destination}")


def process_directory(folder, output_folder, passphrase, mode):
    folder = Path(folder).resolve()
    output_folder = Path(output_folder).resolve()

    if not folder.is_dir():
        raise NotADirectoryError(f"Folder not found: {folder}")

    # Prevent the output folder from being included in the input scan.
    if output_folder == folder or folder in output_folder.parents:
        raise ValueError("Output folder must be outside the input folder.")

    files = [p for p in folder.rglob("*") if p.is_file()]

    if not files:
        print("No files found.")
        return

    success = 0
    failures = 0

    for source in files:
        relative = source.relative_to(folder)

        try:
            if mode == "encrypt":
                destination = output_folder / (str(relative) + ".vault")
                encrypt_file(source, destination, passphrase)
            else:
                if not source.name.endswith(".vault"):
                    continue
                relative_output = Path(str(relative)[:-6])
                destination = output_folder / relative_output
                decrypt_file(source, destination, passphrase)

            success += 1
        except (OSError, ValueError) as error:
            failures += 1
            print(f"ERROR: {source}: {error}")

    print(f"\nFinished. Successful: {success}, Failed: {failures}")


def main():
    parser = argparse.ArgumentParser(
        description="AES-256-GCM file and directory vault"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    for command in ("encrypt", "decrypt"):
        sub = subparsers.add_parser(command)
        sub.add_argument("source", help="Input file or directory")
        sub.add_argument("destination", help="Separate output file or directory")

    args = parser.parse_args()

    passphrase = getpass.getpass("Enter master passphrase: ")
    if not passphrase:
        raise SystemExit("Passphrase cannot be empty.")

    source = Path(args.source)
    destination = Path(args.destination)

    if source.is_dir():
        process_directory(source, destination, passphrase, args.command)
    elif source.is_file():
        if args.command == "encrypt":
            encrypt_file(source, destination, passphrase)
        else:
            decrypt_file(source, destination, passphrase)
    else:
        raise SystemExit(f"Input path does not exist: {source}")


if __name__ == "__main__":
    main()
