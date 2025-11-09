import bcrypt
import uuid

# --- Hashing a password ---
password = b"1q2w3e4r"  # Must be bytes
salt = bcrypt.gensalt()         # Generates a new salt
hashed = bcrypt.hashpw(password, salt)

print("Hashed password:", hashed)

# --- Verifying a password ---
entered_password = b"1q2w3e4r"

if bcrypt.checkpw(entered_password, hashed):
    print("✅ Password match")
else:
    print("❌ Invalid password")

unique_id = uuid.uuid4()

print(unique_id)
print(type(str(unique_id)))

