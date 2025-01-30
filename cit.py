#!/usr/bin/env python3

import click
import base64
import msgpack
import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import (
    rsa,
    dsa,
    ec,
    padding
)

defaultKeyEncoding = serialization.Encoding.DER

def key_encoding_str():
    if defaultKeyEncoding == serialization.Encoding.DER:
        return "DER"
    elif defaultKeyEncoding == serialization.Encoding.PEM:
        return "PEM"
    else:
        return "UNK"


###############################################################################
#                           SERIALIZATION FUNCTIONS
###############################################################################

def serialize_to_bytes(data):
    """
    Serialize the given Python data structure to bytes using MessagePack.

    :param data: Any Python data structure (list, dict, etc.) to be serialized.
    :return: A bytes object containing the serialized data.
    """
    # use_bin_type=True ensures that Python's bytes are properly stored as binary
    return msgpack.packb(data, use_bin_type=True)


def deserialize_from_bytes(packed_data):
    """
    Deserialize MessagePack data from bytes back into a Python object.

    :param packed_data: A bytes object containing the MessagePack-serialized data.
    :return: Python data structure that was read from the MessagePack bytes.
    """
    # raw=False ensures binary data remains bytes, and
    # strings (UTF-8) are decoded into str.
    return msgpack.unpackb(packed_data, raw=False)

###############################################################################
#                           KEY GENERATION FUNCTIONS
###############################################################################

def serialize_private_key_to_b64(private_key) -> str:
    """
    Serialize a private key to DER/PEM (unencrypted) and then Base64-encode it.
    """
    private_der = private_key.private_bytes(
        encoding=defaultKeyEncoding,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return base64.b64encode(private_der).decode("utf-8")


def serialize_public_key_to_b64(public_key) -> str:
    """
    Serialize a public key to DER/PEM and then Base64-encode it.
    """
    public_der = public_key.public_bytes(
        encoding=defaultKeyEncoding,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return base64.b64encode(public_der).decode("utf-8")


def load_public_key(public_key_encoded: bytes):
    """
    Load encoded public key from DER/PEM to public_key structure
    """
    if defaultKeyEncoding == serialization.Encoding.DER:
        return serialization.load_der_public_key(
            public_key_encoded, backend=default_backend()
        )
    elif defaultKeyEncoding == serialization.Encoding.PEM:
        return serialization.load_pem_public_key(
            public_key_encoded, backend=default_backend()
        )
    else:
        raise ValueError(f"Invalid defaultKeyEncoding: {defaultKeyEncoding}")


def load_private_key(private_key_encoded: bytes):
    """
    Load encoded private key from DER/PEM to private_key structure
    """
    if defaultKeyEncoding == serialization.Encoding.DER:
        return serialization.load_der_private_key(
            private_key_encoded, password=None, backend=default_backend()
        )
    elif defaultKeyEncoding == serialization.Encoding.PEM:
        return serialization.load_pem_private_key(
            private_key_encoded, password=None, backend=default_backend()
        )
    else:
        raise ValueError(f"Invalid defaultKeyEncoding: {defaultKeyEncoding}")


def generate_rsa_key_pair(bits=2048):
    """
    Generate an RSA key pair (default 2048 bits).
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=bits,
        backend=default_backend(),
    )
    return private_key, private_key.public_key()


def generate_ec_key_pair(curve_name="SECP256R1"):
    """
    Generate an EC key pair (default curve SECP256R1 = 256-bit).
    """
    curve_map = {
        "SECP192R1": ec.SECP192R1,
        "SECP224R1": ec.SECP224R1,
        "SECP256R1": ec.SECP256R1,
        "SECP384R1": ec.SECP384R1,
        "SECP521R1": ec.SECP521R1,
    }
    curve_class = curve_map[curve_name]
    private_key = ec.generate_private_key(curve_class(), backend=default_backend())
    return private_key, private_key.public_key()


def generate_dsa_key_pair(bits=2048):
    """
    Generate a DSA key pair (default 2048 bits).
    """
    private_key = dsa.generate_private_key(
        key_size=bits,
        backend=default_backend(),
    )
    return private_key, private_key.public_key()


###############################################################################
#                  HYBRID ENCRYPTION FOR RSA (LARGE DATA)
###############################################################################

def hybrid_rsa_encrypt(public_key, plaintext_bytes: bytes) -> bytes:
    """
    RSA Hybrid Encryption:
    1) Generate a random 256-bit AES key (session key).
    2) RSA-encrypt this session key (OAEP + SHA256).
    3) Encrypt data with AES-256-GCM.
    4) Return a structured ciphertext containing:
       RSA_ENC_SESSION_KEY_b64 ::: IV_b64 ::: AES_CIPHERTEXT_b64
    Everything is then base64-encoded again before returning.
    """
    # 1) Generate random AES session key (32 bytes = 256 bits)
    aes_key = os.urandom(32)

    # 2) RSA-encrypt the session key
    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        )
    )

    # 3) Encrypt data with AES-256-GCM
    aesgcm = AESGCM(aes_key)
    iv = os.urandom(12)
    ciphertext = aesgcm.encrypt(iv, plaintext_bytes, None)

    # 4) Structure and final base64
    combined = [
        "hrsa",
        encrypted_key,
        iv,
        ciphertext
    ]
    return serialize_to_bytes(combined)


def hybrid_rsa_decrypt(private_key, blob: bytes) -> bytes:
    """
    RSA Hybrid Decryption:
    1) Base64-decode the entire structure
    2) Parse the RSA-encrypted session key, IV, AES ciphertext
    3) RSA-decrypt the session key
    4) AES-256-GCM decrypt the data
    """
    try:
        combined_decoded = deserialize_from_bytes(blob)
        magic, encrypted_key, iv, ciphertext = combined_decoded
        if magic != "hrsa":
            raise ValueError("invalid magic, not 'hrsa'")

    except Exception as e:
        raise ValueError(f"Malformed RSA ciphertext structure: {e}")

    # RSA-decrypt the session key
    aes_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        )
    )

    # AES-GCM decrypt
    aesgcm = AESGCM(aes_key)
    return aesgcm.decrypt(iv, ciphertext, None)


###############################################################################
#    EPHEMERAL EC & DSA ENCRYPTION (ALSO HYBRID, BUT VIA DIFFIE-HELLMAN)
###############################################################################

def ephemeral_ec_encrypt(public_key, plaintext_bytes: bytes) -> bytes:
    """
    Ephemeral ECDH + AES-256-GCM.
    """
    ephemeral_private_key = ec.generate_private_key(
        public_key.curve, backend=default_backend()
    )
    shared_secret = ephemeral_private_key.exchange(ec.ECDH(), public_key)

    # Derive AES key
    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"EC_Ephemeral_Encryption",
        backend=default_backend(),
    ).derive(shared_secret)

    # Encrypt
    aesgcm = AESGCM(aes_key)
    iv = os.urandom(12)
    ciphertext = aesgcm.encrypt(iv, plaintext_bytes, None)

    eph_pub_encoded = ephemeral_private_key.public_key().public_bytes(
        encoding=defaultKeyEncoding,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    combined = [
        "ec",
        eph_pub_encoded,
        iv,
        ciphertext
    ]
    return serialize_to_bytes(combined)


def ephemeral_ec_decrypt(private_key, blob: bytes) -> bytes:
    """
    Decrypt ephemeral EC ciphertext.
    """
    try:
        combined_decoded = deserialize_from_bytes(blob)
        magic, eph_pub_encoded, iv, ciphertext = combined_decoded
        if magic != "ec":
            raise ValueError("invalid magic, not 'ec'")
    except Exception as e:
        raise ValueError(f"Malformed EC ciphertext structure: {e}")

    ephemeral_pub_key = load_public_key(eph_pub_encoded)

    shared_secret = private_key.exchange(ec.ECDH(), ephemeral_pub_key)
    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"EC_Ephemeral_Encryption",
        backend=default_backend(),
    ).derive(shared_secret)

    aesgcm = AESGCM(aes_key)
    return aesgcm.decrypt(iv, ciphertext, None)


def ephemeral_dsa_encrypt(public_key, plaintext_bytes: bytes) -> bytes:
    """
    Ephemeral "DH" using DSA parameters + AES-256-GCM (non-standard usage).
    """
    dsa_pub_nums = public_key.public_numbers()
    p = dsa_pub_nums.parameter_numbers.p
    g = dsa_pub_nums.parameter_numbers.g
    y = dsa_pub_nums.y

    x_e = int.from_bytes(os.urandom(32), "big") % (p - 1)
    y_e = pow(g, x_e, p)  # ephemeral public
    s = pow(y, x_e, p)    # shared secret
    shared_secret = s.to_bytes((s.bit_length() + 7) // 8, "big")

    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"DSA_Ephemeral_Encryption",
        backend=default_backend(),
    ).derive(shared_secret)

    aesgcm = AESGCM(aes_key)
    iv = os.urandom(12)
    ciphertext = aesgcm.encrypt(iv, plaintext_bytes, None)

    combined = [
        "dsa",
        str(y_e),
        iv,
        ciphertext
    ]
    return serialize_to_bytes(combined)


def ephemeral_dsa_decrypt(private_key, blob: bytes) -> bytes:
    """
    Decrypt ephemeral DSA ciphertext.
    """
    try:
        combined_decoded = deserialize_from_bytes(blob)
        magic, y_e_s, iv, ciphertext = combined_decoded
        if magic != "dsa":
            raise ValueError("invalid magic, not 'dsa'")
    except Exception as e:
        raise ValueError(f"Malformed DSA ciphertext structure: {e}")

    y_e = int(y_e_s)

    dsa_priv_nums = private_key.private_numbers()
    x = dsa_priv_nums.x
    p = dsa_priv_nums.public_numbers.parameter_numbers.p

    s = pow(y_e, x, p)
    shared_secret = s.to_bytes((s.bit_length() + 7) // 8, "big")

    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"DSA_Ephemeral_Encryption",
        backend=default_backend(),
    ).derive(shared_secret)

    aesgcm = AESGCM(aes_key)
    return aesgcm.decrypt(iv, ciphertext, None)


###############################################################################
#          UNIFIED ENCRYPT/DECRYPT DISPATCH FOR RSA, EC, DSA
###############################################################################

def encrypt_data(public_key_b64: str, plaintext: bytes) -> bytes:
    """
    Dispatch encryption based on the type of public key:
      - RSA: Hybrid approach (AES-256-GCM + RSA-encrypted key)
      - EC: Ephemeral ECDH + AES-256-GCM
      - DSA: Ephemeral “DH” + AES-256-GCM
    Returns Base64-encoded ciphertext.
    """
    try:
        pub_encoded = base64.b64decode(public_key_b64)
        pub_key = load_public_key(pub_encoded)
    except Exception as e:
        raise ValueError(f"Failed to load public key: {e}")

    if isinstance(pub_key, rsa.RSAPublicKey):
        return hybrid_rsa_encrypt(pub_key, plaintext)
    elif isinstance(pub_key, ec.EllipticCurvePublicKey):
        return ephemeral_ec_encrypt(pub_key, plaintext)
    elif isinstance(pub_key, dsa.DSAPublicKey):
        return ephemeral_dsa_encrypt(pub_key, plaintext)
    else:
        raise ValueError("Unsupported public key type for encryption.")


def decrypt_data(private_key_b64: str, ciphertext: bytes) -> bytes:
    """
    Dispatch decryption based on the type of private key:
      - RSA: Hybrid approach
      - EC: Ephemeral ECDH
      - DSA: Ephemeral “DH”
    Returns the raw plaintext bytes.
    """
    try:
        priv_pem = base64.b64decode(private_key_b64)
        priv_key = load_private_key(priv_pem)
    except Exception as e:
        raise ValueError(f"Failed to load private key: {e}")

    if isinstance(priv_key, rsa.RSAPrivateKey):
        return hybrid_rsa_decrypt(priv_key, ciphertext)
    elif isinstance(priv_key, ec.EllipticCurvePrivateKey):
        return ephemeral_ec_decrypt(priv_key, ciphertext)
    elif isinstance(priv_key, dsa.DSAPrivateKey):
        return ephemeral_dsa_decrypt(priv_key, ciphertext)
    else:
        raise ValueError("Unsupported private key type for decryption.")


###############################################################################
#                               CLICK CLI
###############################################################################
@click.group()
def cli():
    """
    CLI that generates keys (RSA, EC, DSA) with secure defaults and performs
    hybrid encryption/decryption of strings or files:
      - RSA: AES-256 session key encrypted with RSA (OAEP)
      - EC: ephemeral ECDH + AES-256-GCM
      - DSA: ephemeral “DH” + AES-256-GCM

    Subcommands:
      create-rsa    (default 2048 bits)
      create-ec     (default SECP256R1)
      create-dsa    (default 2048 bits)
      encrypt       (encrypt a string)
      decrypt       (decrypt a string)
      encrypt-file  (encrypt a file, any size)
      decrypt-file  (decrypt a file)
    """


#
# KEY CREATION
#
@cli.command(name="create-rsa")
@click.option("--bits", default=2048, show_default=True,
              help="RSA key size (2048 is a common secure minimum).")
def create_rsa(bits):
    """
    Generate an RSA key pair (default 2048 bits).
    Print private & public keys in Base64-encoded DER.
    """
    priv, pub = generate_rsa_key_pair(bits)
    priv_b64 = serialize_private_key_to_b64(priv)
    pub_b64 = serialize_public_key_to_b64(pub)

    click.echo(f"=== RSA {bits}-BIT KEY PAIR ===\n")
    click.echo("Private Key (Base64):\n")
    click.echo(priv_b64)
    click.echo("\nPublic Key (Base64):\n")
    click.echo(pub_b64)


@cli.command(name="create-ec")
@click.option("--curve", default="SECP256R1", show_default=True,
    type=click.Choice(["SECP192R1","SECP224R1","SECP256R1","SECP384R1","SECP521R1"]),
    help="Elliptic curve. SECP256R1 is 256-bit (good default).")
def create_ec(curve):
    """
    Generate an EC key pair on the given curve (default SECP256R1 = 256 bits).
    Print private & public keys in Base64-encoded DER.
    """
    priv, pub = generate_ec_key_pair(curve)
    priv_b64 = serialize_private_key_to_b64(priv)
    pub_b64 = serialize_public_key_to_b64(pub)

    click.echo(f"=== EC KEY PAIR on {curve} ===\n")
    click.echo("Private Key (Base64):\n")
    click.echo(priv_b64)
    click.echo("\nPublic Key (Base64):\n")
    click.echo(pub_b64)


@cli.command(name="create-dsa")
@click.option("--bits", default=2048, show_default=True,
              help="DSA key size. 2048 bits is the usual secure minimum.")
def create_dsa(bits):
    """
    Generate a DSA key pair (default 2048 bits).
    Print private & public keys in Base64-encoded DER.

    (Typically used for signatures; here we support ephemeral encryption for demo.)
    """
    priv, pub = generate_dsa_key_pair(bits)
    priv_b64 = serialize_private_key_to_b64(priv)
    pub_b64 = serialize_public_key_to_b64(pub)

    click.echo(f"=== DSA {bits}-BIT KEY PAIR ===\n")
    click.echo("Private Key (Base64):\n")
    click.echo(priv_b64)
    click.echo("\nPublic Key (Base64):\n")
    click.echo(pub_b64)


#
# STRING ENCRYPTION / DECRYPTION
#
@cli.command()
@click.option("--public-key", required=True, help="Base64-encoded PEM public key (RSA/EC/DSA).")
@click.option("--message", required=True, help="Plaintext message to encrypt.")
def encrypt(public_key, message):
    """
    Encrypt a plaintext string using RSA/EC/DSA:
      - RSA => Hybrid (AES-256 + RSA OAEP)
      - EC/DSA => ephemeral DH + AES-256-GCM
    Outputs Base64 ciphertext.
    """
    plaintext_bytes = message.encode("utf-8")
    try:
        ciphertext = encrypt_data(public_key, plaintext_bytes)
        ciphertext_b64 = base64.b64encode(ciphertext)
    except Exception as e:
        click.echo(f"Encryption error: {e}")
        return

    # ciphertext_b64 is already base64-encoded
    click.echo(ciphertext_b64.decode("utf-8"))


@cli.command()
@click.option("--private-key", required=True, help="Base64-encoded PEM private key (RSA/EC/DSA).")
@click.option("--ciphertext", required=True, help="Base64-encoded ciphertext.")
def decrypt(private_key, ciphertext):
    """
    Decrypt a Base64-encoded ciphertext:
      - RSA => Hybrid
      - EC/DSA => ephemeral DH
    """
    try:
        ciphertext_b64 = ciphertext.encode("utf-8")
        plaintext_bytes = decrypt_data(private_key, base64.b64decode(ciphertext_b64))
    except Exception as e:
        click.echo(f"Decryption error: {e}")
        return

    click.echo(plaintext_bytes.decode("utf-8", errors="replace"))


#
# FILE ENCRYPTION / DECRYPTION
#
@cli.command(name="encrypt-file")
@click.option("--public-key", required=True, help="Base64 PEM public key (RSA/EC/DSA).")
@click.option("--input-file", required=True, type=click.Path(exists=True, dir_okay=False),
              help="Path to the plaintext file.")
@click.option("--output-file", required=False, type=click.Path(dir_okay=False),
              help="Path for the Base64 ciphertext. If omitted, prints to stdout.")
def encrypt_file_command(public_key, input_file, output_file):
    """
    Encrypt a file:
      - RSA => Hybrid (AES-256 key, RSA-encrypted)
      - EC/DSA => ephemeral DH + AES-256-GCM
    Writes binary ciphertext to file or stdout.
    """
    try:
        with open(input_file, "rb") as f:
            plaintext = f.read()
    except Exception as e:
        click.echo(f"Could not read file '{input_file}': {e}")
        return

    try:
        ciphertext = encrypt_data(public_key, plaintext)
    except Exception as e:
        click.echo(f"Encryption error: {e}")
        return

    if output_file:
        try:
            with open(output_file, "wb") as out_f:
                out_f.write(ciphertext)
        except Exception as e:
            click.echo(f"Could not write ciphertext to '{output_file}': {e}")
    else:
        ciphertext_b64 = base64.b64encode(ciphertext)
        click.echo(ciphertext_b64.decode("utf-8", errors="replace"))


@cli.command(name="decrypt-file")
@click.option("--private-key", required=True, help="Base64 PEM private key (RSA/EC/DSA).")
@click.option("--input-file", required=True, type=click.Path(exists=True, dir_okay=False),
              help="Path to the Base64-encoded ciphertext file.")
@click.option("--output-file", required=False, type=click.Path(dir_okay=False),
              help="Path for the decrypted plaintext. If omitted, prints to stdout.")
def decrypt_file_command(private_key, input_file, output_file):
    """
    Decrypt a file:
      - RSA => Hybrid
      - EC/DSA => ephemeral DH + AES-256-GCM
    Expects binary ciphertext in `input-file`.
    """
    try:
        with open(input_file, "rb") as in_f:
            ciphertext = in_f.read()
    except Exception as e:
        click.echo(f"Could not read file '{input_file}': {e}")
        return

    try:
        plaintext = decrypt_data(private_key, ciphertext)
    except Exception as e:
        click.echo(f"Decryption error: {e}")
        return

    if output_file:
        # If the original data was text, this will still just write raw bytes.
        # If you know it's text, you could decode it. We'll assume bytes are fine.
        try:
            with open(output_file, "wb") as out_f:
                out_f.write(plaintext)
        except Exception as e:
            click.echo(f"Could not write plaintext to '{output_file}': {e}")
    else:
        plaintext_b64 = base64.b64encode(plaintext)
        click.echo(plaintext_b64.decode("utf-8", errors="replace"))


###############################################################################
#                               MAIN
###############################################################################
if __name__ == "__main__":
    cli()
