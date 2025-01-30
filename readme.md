#Usage & Highlights

##Install Requirements

```
pip install -r requirements.txt
```

##Run Tests
```
pytest -v test_cit.py
```

##Install
(in editable mode or normal)

```
pip install -e .
```

or

```
pip install .
```

##View Help

```
./cit.py --help
```

You should see the subcommands:
	•	create-rsa
	•	create-ec
	•	create-dsa
	•	encrypt
	•	decrypt
	•	encrypt-file
	•	decrypt-file

#Generating Keys (Short & Insecure)
##RSA
(default 2048 bits):

```
./cit.py create-rsa
```
Prints Base64-encoded PEM keys for private/public.

##EC
(default SECP256R1):
```
./cit.py create-ec
```

##DSA
(default 2048 bits):
```
./cit.py create-dsa
```

#Encrypt / Decrypt (Strings)
##Encrypt a String:

```
./cit.py encrypt \
  --public-key "<BASE64_PEM_PUBLIC_KEY>" \
  --message "Hello from short keys!"
```

Outputs Base64 ciphertext (a single line).

##Decrypt a String:
```
./cit.py decrypt \
  --private-key "<BASE64_PEM_PRIVATE_KEY>" \
  --ciphertext "<BASE64_CIPHERTEXT>"
```

Prints the original message.

Under the hood:
* RSA uses direct OAEP with SHA256 (okay for small data).
* EC uses an ephemeral ECDH to derive an AES-256-GCM key.
* DSA uses ephemeral Diffie-Hellman (non-standard usage) to derive an AES-256-GCM key.

#Encrypt / Decrypt (Files)
##Encrypt a File:

```
./cit.py encrypt-file \
  --public-key "<BASE64_PEM_PUBLIC_KEY>" \
  --input-file secret.txt \
  --output-file secret.enc
```
* Reads secret.txt.
* Outputs Base64 ciphertext to secret.enc.

##Decrypt a File:

```
./cit.py decrypt-file \
  --private-key "<BASE64_PEM_PRIVATE_KEY>" \
  --input-file secret.enc \
  --output-file secret.decrypted
```

* Reads Base64 ciphertext from secret.enc.
* Writes decrypted data to secret.decrypted.

Note: Because RSA here is short (512 bits) and we do direct RSA encryption, it will break if the file is larger than the RSA limit (roughly 53 bytes for 512-bit RSA with OAEP!).
For EC/DSA ephemeral encryption, we do AES-256-GCM under the hood, so it can handle somewhat larger files. But everything is still a demo—do not use short keys in production.

# RSA Hybrid Encryption

For RSA, we now:
1.	Generate a random 256-bit AES key (the “session key”).
2.	Encrypt this session key with RSA (OAEP + SHA256).
3.	Encrypt the data with AES-256-GCM.
4.	Combine the RSA-encrypted key, AES IV, and AES ciphertext into a single structured message.


# Final Warnings

1.	Short Keys Are Easily Broken
512-bit RSA or 192-bit EC are trivially breakable today.
2.	DSA & EC
	* Typically used for signing or key exchange, not raw encryption.
	* Our ephemeral approach is a demonstration of how you could wrap an ephemeral Diffie-Hellman handshake into a file/string encryption scheme. It is not a standard approach.
3.	Hybrid Encryption
	* RSA is often used to encrypt a random AES key for large data, not the data itself.
	* Direct RSA encryption of large files is impractical.
4.	Use Modern, Secure Parameters
	* RSA ≥2048 bits
	* EC ≥ SECP256R1
	* DSA ≥2048 bits (though DSA is largely outdated; Ed25519 or ECDSA are more common for signatures).

This script is strictly for educational exploration of cryptographic APIs and Click subcommands.
