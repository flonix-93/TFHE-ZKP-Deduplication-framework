import hashlib
import os

def compute_hash(file_path):
    hasher = hashlib.sha256()
    with open(file_path, 'rb') as f:
        buf = f.read()
        hasher.update(buf)
    return hasher.hexdigest()

def is_duplicate(file_path, log_path):
    new_hash = compute_hash(file_path)
    if not os.path.exists(log_path):
        with open(log_path, 'w') as log_file:
            log_file.write('')

    with open(log_path, 'r') as log_file:
        logged_hashes = log_file.read().splitlines()

    if new_hash in logged_hashes:
        return True, new_hash

    with open(log_path, 'a') as log_file:
        log_file.write(new_hash + '\n')

    return False, new_hash