import re
import tempfile
import os

import pytest
from click.testing import CliRunner

# Import the CLI group from your script
from cit import cli

# ---------------------------------------------------------------------------
# HELPER FUNCTIONS
# ---------------------------------------------------------------------------

def extract_keys(output: str):
    """
    Given the output of a 'create-*' command, parse out the private key and public key
    in Base64-encoded PEM.

    We expect something like:

        === RSA 2048-BIT KEY PAIR ===

        Private Key (Base64 PEM):

        LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBL...
        ...
        Public Key (Base64 PEM):

        LS0tLS1CRUdJTiBSU0EgUFVCTElDIEtF...
        ...
    """
    # Regex to capture lines between the markers
    priv_key_pattern = re.compile(
        r"Private Key \(Base64 PEM\):\s+(.*?)\s+Public Key \(Base64 PEM\):",
        re.DOTALL,
    )
    pub_key_pattern = re.compile(
        r"Public Key \(Base64 PEM\):\s+(.*)$",
        re.DOTALL,
    )

    priv_match = priv_key_pattern.search(output)
    pub_match = pub_key_pattern.search(output)

    if not priv_match or not pub_match:
        raise ValueError("Could not parse private/public key from output")

    # Clean up extraneous whitespace
    private_key = priv_match.group(1).strip()
    public_key = pub_match.group(1).strip()
    return private_key, public_key


def roundtrip_string_test(runner: CliRunner, private_key: str, public_key: str):
    """
    1. Encrypt a string with 'encrypt' using the public key
    2. Decrypt with 'decrypt' using the private key
    3. Assert we get the original string
    """
    ORIGINAL = "Hello from pytest!"

    # Encrypt
    result_enc = runner.invoke(
        cli,
        [
            "encrypt",
            "--public-key", public_key,
            "--message", ORIGINAL,
        ],
    )
    assert result_enc.exit_code == 0, f"Encrypt failed: {result_enc.output}"
    ciphertext = result_enc.output.strip()

    # Decrypt
    result_dec = runner.invoke(
        cli,
        [
            "decrypt",
            "--private-key", private_key,
            "--ciphertext", ciphertext,
        ],
    )
    assert result_dec.exit_code == 0, f"Decrypt failed: {result_dec.output}"
    decrypted = result_dec.output.strip()

    assert decrypted == ORIGINAL, "Decrypted text did not match original"


def roundtrip_file_test(runner: CliRunner, private_key: str, public_key: str):
    """
    1. Write a temp file with sample data
    2. Encrypt it using 'encrypt-file' with the public key
    3. Decrypt the ciphertext using 'decrypt-file' with the private key
    4. Verify we get the original file contents
    """
    ORIGINAL_CONTENT = b"Hello from pytest file encryption!"

    with tempfile.NamedTemporaryFile(delete=False) as f_plain:
        f_plain_name = f_plain.name
        f_plain.write(ORIGINAL_CONTENT)

    try:
        # Prepare temp file for ciphertext
        with tempfile.NamedTemporaryFile(delete=False) as f_enc:
            f_enc_name = f_enc.name

        # Encrypt the file
        result_enc = runner.invoke(
            cli,
            [
                "encrypt-file",
                "--public-key", public_key,
                "--input-file", f_plain_name,
                "--output-file", f_enc_name,
            ],
        )
        assert result_enc.exit_code == 0, f"encrypt-file failed: {result_enc.output}"

        # Prepare temp file for decrypted content
        with tempfile.NamedTemporaryFile(delete=False) as f_dec:
            f_dec_name = f_dec.name

        # Decrypt the file
        result_dec = runner.invoke(
            cli,
            [
                "decrypt-file",
                "--private-key", private_key,
                "--input-file", f_enc_name,
                "--output-file", f_dec_name,
            ],
        )
        assert result_dec.exit_code == 0, f"decrypt-file failed: {result_dec.output}"

        # Read back the decrypted file
        with open(f_dec_name, "rb") as f_in:
            decrypted_content = f_in.read()

        assert decrypted_content == ORIGINAL_CONTENT, "File content mismatch!"

    finally:
        # Clean up temp files
        for fname in (f_plain_name, f_enc_name, f_dec_name):
            if os.path.exists(fname):
                os.remove(fname)


def algorithm_test(runner: CliRunner, create_command: list):
    """
    General test for:
     - Key generation (via create_command)
     - Round-trip string encryption/decryption
     - Round-trip file encryption/decryption
    """
    # 1) Generate keys
    result_create = runner.invoke(cli, create_command)
    assert result_create.exit_code == 0, f"Key generation failed: {result_create.output}"

    private_key, public_key = extract_keys(result_create.output)

    # 2) String encryption/decryption
    roundtrip_string_test(runner, private_key, public_key)

    # 3) File encryption/decryption
    roundtrip_file_test(runner, private_key, public_key)


# ---------------------------------------------------------------------------
# TEST CASES
# ---------------------------------------------------------------------------

def test_rsa():
    runner = CliRunner()
    # create an RSA key pair (2048 bits)
    algorithm_test(runner, ["create-rsa", "--bits=2048"])


def test_ec():
    runner = CliRunner()
    # create an EC key pair (SECP256R1)
    algorithm_test(runner, ["create-ec", "--curve=SECP256R1"])


def test_dsa():
    runner = CliRunner()
    # create a DSA key pair (2048 bits)
    algorithm_test(runner, ["create-dsa", "--bits=2048"])
