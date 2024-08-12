import hashlib
import random

def generate_proof(data):
    # Simulate proof generation using a simple hash-based scheme
    random_number = random.randint(0, 1 << 256)
    data_hash = hashlib.sha256(data.encode()).hexdigest()
    combined = f"{data_hash}{random_number}"
    proof = hashlib.sha256(combined.encode()).hexdigest()
    return proof, random_number

def verify_proof(data, proof, random_number):
    # Simulate proof verification using the same hash-based scheme
    data_hash = hashlib.sha256(data.encode()).hexdigest()
    combined = f"{data_hash}{random_number}"
    expected_proof = hashlib.sha256(combined.encode()).hexdigest()
    return proof == expected_proof
