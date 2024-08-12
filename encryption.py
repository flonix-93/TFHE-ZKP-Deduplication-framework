import seal
import numpy as np
import time
import os
from concurrent.futures import ThreadPoolExecutor

def encrypt_chunk(chunk_array, encoder, encryptor):
    plain = encoder.encode(chunk_array)
    encrypted = encryptor.encrypt(plain)
    return encrypted

def decrypt_chunk(encrypted, decryptor, encoder):
    plain_result = decryptor.decrypt(encrypted)
    decoded_result = np.array(encoder.decode(plain_result), dtype=np.int64)
    return decoded_result

def save_encrypted_data(encrypted_data, folder_path):
    os.makedirs(folder_path, exist_ok=True)
    for idx, encrypted in enumerate(encrypted_data):
        file_path = os.path.join(folder_path, f'encrypted_chunk_{idx}.bin')
        with open(file_path, 'wb') as file:
            encrypted.save(file.name)

def load_encrypted_data(folder_path, context):
    encrypted_data = []
    for file_name in sorted(os.listdir(folder_path)):
        file_path = os.path.join(folder_path, file_name)
        encrypted = seal.Ciphertext(context)
        with open(file_path, 'rb') as file:
            encrypted.load(file.name)
        encrypted_data.append(encrypted)
    return encrypted_data

def homomorphic_dot_product(encrypted_chunks, evaluator, relin_keys):
    start_time = time.time()
    result = evaluator.multiply(encrypted_chunks[0], encrypted_chunks[0])
    evaluator.relinearize_inplace(result, relin_keys)
    for i in range(1, len(encrypted_chunks)):
        temp = evaluator.multiply(encrypted_chunks[i], encrypted_chunks[i])
        evaluator.relinearize_inplace(temp, relin_keys)
        result = evaluator.add(result, temp)
        evaluator.relinearize_inplace(result, relin_keys)
    end_time = time.time()
    print(f"Time for homomorphic dot product: {end_time - start_time} seconds")
    return result

def integrated_encryption_system(input_path, encrypted_folder, decrypted_path):
    results = {}
    total_start_time = time.time()

    # Setup parameters
    start_time = time.time()
    parms = seal.EncryptionParameters(seal.scheme_type.bfv)
    parms.set_poly_modulus_degree(4096)
    parms.set_coeff_modulus(seal.CoeffModulus.BFVDefault(4096))
    parms.set_plain_modulus(seal.PlainModulus.Batching(4096, 20))
    context = seal.SEALContext(parms)
    end_time = time.time()
    setup_time = end_time - start_time
    print(f"Time for parameter setup: {setup_time} seconds")
    results['Parameter Setup Time'] = setup_time

    # Key generation
    start_time = time.time()
    keygen = seal.KeyGenerator(context)
    public_key = keygen.create_public_key()
    secret_key = keygen.secret_key()
    relin_keys = keygen.create_relin_keys()
    galois_keys = keygen.create_galois_keys()
    encryptor = seal.Encryptor(context, public_key)
    evaluator = seal.Evaluator(context)
    decryptor = seal.Decryptor(context, secret_key)
    encoder = seal.BatchEncoder(context)
    end_time = time.time()
    keygen_time = end_time - start_time
    print(f"Time for key generation: {keygen_time} seconds")
    results['Key Generation Time'] = keygen_time

    # Read input file with buffered I/O
    start_time = time.time()
    with open(input_path, 'r') as file:
        data = file.read().strip()
    end_time = time.time()
    read_time = end_time - start_time
    print(f"Time for reading input file: {read_time} seconds")
    results['Input File Read Time'] = read_time

    # Convert text to integers for encryption
    data_integers = [ord(char) for char in data]
    chunk_size = encoder.slot_count()

    encrypted_chunks = []
    total_encryption_time = 0

    # Encrypt the data in chunks using parallel processing
    start_time = time.time()
    with ThreadPoolExecutor(max_workers=os.cpu_count()) as executor:
        futures = []
        for i in range(0, len(data_integers), chunk_size):
            chunk = data_integers[i:i + chunk_size]
            chunk_array = np.array(chunk, dtype=np.int64)
            futures.append(executor.submit(encrypt_chunk, chunk_array, encoder, encryptor))

        for future in futures:
            encrypted_chunks.append(future.result())
    end_time = time.time()
    total_encryption_time += end_time - start_time
    print(f"Total time for encryption: {total_encryption_time} seconds")
    results['Encryption Time'] = total_encryption_time

    # Save encrypted data with buffered I/O
    start_time = time.time()
    save_encrypted_data(encrypted_chunks, encrypted_folder)
    end_time = time.time()
    save_time = end_time - start_time
    print(f"Time for saving encrypted data: {save_time} seconds")
    results['Encrypted Data Save Time'] = save_time

    # Perform homomorphic dot product on encrypted chunks
    start_time = time.time()
    dot_product_result = homomorphic_dot_product(encrypted_chunks, evaluator, relin_keys)
    encrypted_chunks.append(dot_product_result)
    dot_product_time = time.time() - start_time
    print("Homomorphic dot product performed on encrypted chunks.")
    results['Homomorphic Dot Product Time'] = dot_product_time

    # Decrypt the dot product result to obtain the plaintext result
    dot_product_plaintext = decrypt_chunk(dot_product_result, decryptor, encoder)
    dot_product_value = dot_product_plaintext[0]  # Assume first element is the result
    results['Homomorphic Dot Product Result'] = dot_product_value

    decrypted_data = []
    total_decryption_time = 0

    # Decrypt the data in chunks using parallel processing
    start_time = time.time()
    with ThreadPoolExecutor(max_workers=os.cpu_count()) as executor:
        futures = []
        for encrypted in encrypted_chunks:
            futures.append(executor.submit(decrypt_chunk, encrypted, decryptor, encoder))

        for future in futures:
            decrypted_data.extend(future.result())
    end_time = time.time()
    total_decryption_time += end_time - start_time
    print(f"Total time for decryption: {total_decryption_time} seconds")
    results['Decryption Time'] = total_decryption_time

    # Save decrypted data with buffered I/O
    start_time = time.time()
    decrypted_text = ''.join([chr(i) for i in decrypted_data[:len(data_integers)]])
    with open(decrypted_path, 'w') as file:
        file.write(decrypted_text)
    end_time = time.time()
    decrypt_save_time = end_time - start_time
    print(f"Time for saving decrypted data: {decrypt_save_time} seconds")
    results['Decrypted Data Save Time'] = decrypt_save_time

    # Measure total execution time
    total_end_time = time.time()
    total_execution_time = total_end_time - total_start_time
    print(f"Total execution time: {total_execution_time} seconds")
    results['Total Execution Time'] = total_execution_time

    return results

# Example usage
if _name_ == "_main_":
    input_file = 'example.txt'
    encrypted_folder = 'encrypted_chunks'
    decrypted_file = 'example_decrypted.txt'

    integrated_encryption_system(input_file, encrypted_folder, decrypted_file)