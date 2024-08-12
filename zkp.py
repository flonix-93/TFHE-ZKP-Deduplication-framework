import hashlib
import random

# Large prime number for modular arithmetic
p = 2**256 - 189
# Generator for the group
g = 2

def hash_function(data):
    # Hash the input data using SHA-256 and convert to an integer
    result = int(hashlib.sha256(data.encode()).hexdigest(), 16)
    print(f"Hash of data ({data}): {result}")
    return result

def generate_proof(secret):
    # Step 1: Prover's secret (derived from file hash)
    x = secret
    # Compute h = g^x % p
    h = pow(g, x, p)
    print(f"Prover's secret (x): {x}")
    print(f"Computed h = g^x % p: {h}")

    # Step 2: Prover chooses a random number r
    r = random.randint(1, p-1)
    # Compute t = g^r % p
    t = pow(g, r, p)
    print(f"Random number (r): {r}")
    print(f"Computed t = g^r % p: {t}")

    # Step 3: Prover computes challenge c using a hash function
    c = hash_function(f"{g}{h}{t}") % p
    print(f"Computed challenge (c): {c}")

    # Step 4: Prover computes response s
    s = (r + c * x) % (p-1)
    print(f"Computed response (s): {s}")

    return (t, c, s, h)

def verify_proof(g, h, p, t, c, s):
    print(f"Verification process with values:\n g: {g}\n h: {h}\n p: {p}\n t: {t}\n c: {c}\n s: {s}")
    # Compute t' = (g^s * h^-c) % p
    t_prime = (pow(g, s, p) * pow(h, -c, p)) % p
    print(f"Computed t' = (g^s * h^-c) % p: {t_prime}")
    # Check if t' equals t
    return t_prime, t_prime == t

def hash_large_file(file_path):
    BUF_SIZE = 65536  # Read file in chunks of 64KB
    sha256 = hashlib.sha256()
    with open(file_path, 'rb') as f:
        while chunk := f.read(BUF_SIZE):
            sha256.update(chunk)
    file_hash = sha256.digest()
    print(f"Hash of file ({file_path}): {file_hash.hex()}")
    return file_hash

def generate_file_proof(file_path):
    file_hash = hash_large_file(file_path)
    # Convert file hash to integer and use as secret
    secret = int.from_bytes(file_hash, 'big') % p
    print(f"Derived secret from file hash: {secret}")
    # Generate ZKP
    t, c, s, h = generate_proof(secret)
    return file_hash, (t, c, s, h)

def verify_file_proof(file_path, file_hash, proof):
    t, c, s, h = proof
    new_file_hash = hash_large_file(file_path)
    if new_file_hash != file_hash:
        print("File hash mismatch. Proof verification failed.")
        return False, None
    secret = int.from_bytes(file_hash, 'big') % p
    t_prime, valid = verify_proof(g, h, p, t, c, s)
    return valid, t_prime