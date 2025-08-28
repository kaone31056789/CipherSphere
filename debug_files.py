import sqlite3
import os

# Connect to the database
conn = sqlite3.connect('instance/ciphersphere.db')
cursor = conn.cursor()

# Get all encrypted files
cursor.execute("SELECT * FROM encrypted_file")
files = cursor.fetchall()

print("Database files:")
print("ID | User ID | Filename | Original Filename | Algorithm | Size | Text | Favorite | Created")
print("-" * 100)
for file in files:
    print(f"{file[0]} | {file[1]} | {file[2]} | {file[3]} | {file[4]} | {file[5]} | {file[6]} | {file[7]} | {file[8]}")

print("\nVault folder contents:")
vault_path = "ciphersphere/vault"
if os.path.exists(vault_path):
    for file in os.listdir(vault_path):
        file_path = os.path.join(vault_path, file)
        size = os.path.getsize(file_path) if os.path.isfile(file_path) else 0
        print(f"{file} - {size} bytes")
else:
    print("Vault folder not found")

conn.close()
