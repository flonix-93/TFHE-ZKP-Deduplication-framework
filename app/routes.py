from flask import request, render_template, current_app
from werkzeug.utils import secure_filename
import os
from deduplication import is_duplicate
from zkp import generate_file_proof, verify_file_proof
from encryption import integrated_encryption_system
import json
import numpy as np

@current_app.route('/')
def index():
    return render_template('index.html')

@current_app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return render_template('index.html', error='No file part')

    file = request.files['file']

    if file.filename == '':
        return render_template('index.html', error='No selected file')

    if file:
        filename = secure_filename(file.filename)
        file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)

        # Deduplication check
        is_dup, file_hash = is_duplicate(file_path, current_app.config['DEDUPLICATION_LOG'])
        if is_dup:
            os.remove(file_path)
            return render_template('index.html', message='Duplicate file detected and removed.')

        # Generate and verify proof
        file_hash, proof = generate_file_proof(file_path)
        print(f"Generated proof: {proof}")

        proof_valid, t_prime = verify_file_proof(file_path, file_hash, proof)
        if not proof_valid:
            print("Proof verification failed.")
            return render_template('index.html', error='Proof verification failed')
        print("Proof verification successful.")

        # Encryption and decryption
        encrypted_path = os.path.join(current_app.config['ENCRYPTED_FOLDER'], f"{filename}.bin")
        decrypted_path = os.path.join(current_app.config['DECRYPTED_FOLDER'], f"dec_{filename}")

        # Capture encryption and decryption times
        encryption_results = integrated_encryption_system(file_path, encrypted_path, decrypted_path)

        # Convert numpy types to native Python types for JSON serialization
        def convert_to_native_types(results):
            converted_results = {}
            for key, value in results.items():
                if isinstance(value, np.generic):  # Check for any numpy scalar types
                    converted_results[key] = value.item()  # Convert to native Python type
                else:
                    converted_results[key] = value
            return converted_results

        native_encryption_results = convert_to_native_types(encryption_results)

        proof_dict = {
            "t": proof[0],
            "c": proof[1],
            "s": proof[2],
            "h": proof[3],
            "t_prime": t_prime,
            "valid": proof_valid
        }

        # Save results to a JSON file
        with open('results.json', 'w') as result_file:
            json.dump(native_encryption_results, result_file)

        return render_template('index.html', message='File uploaded, encrypted, and processed successfully.', proof=proof_dict)

    return render_template('index.html', error='File upload failed')

@current_app.route('/clear_log', methods=['POST'])
def clear_log():
    log_file_path = current_app.config['DEDUPLICATION_LOG']
    # Clear the log file
    with open(log_file_path, 'w') as file:
        file.write('')
    print("Deduplication log cleared.")
    return render_template('index.html', message='Deduplication log cleared.')

@current_app.route('/get_results', methods=['POST'])
def get_results():
    try:
        with open('results.json', 'r') as result_file:
            results = json.load(result_file)
        return render_template('index.html', message='Results fetched successfully.', results=results)
    except FileNotFoundError:
        return render_template('index.html', error='Results not available.')