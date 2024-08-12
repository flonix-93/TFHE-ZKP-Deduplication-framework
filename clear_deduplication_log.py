log_file_path = 'deduplication_log.txt'

# Clear the log file
with open(log_file_path, 'w') as file:
    file.write('')

print("Deduplication log cleared.")
