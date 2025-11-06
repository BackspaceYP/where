import mysql.connector
from cryptography.fernet import Fernet
import os
import getpass

# --- Configuration ---

# MySQL Database Details
DB_CONFIG = {
    "host": "localhost",
    "user": "where", 
    "password": "where@123", 
    "database": "password_db" 
}

# File to store the encryption key.
KEY_FILE = "secret.key"

#Security Functions 

def generate_key_and_save():
    """Generates a new Fernet key."""
    # A Fernet key must be 32 URL-safe base64-encoded bytes.
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as key_file:
        key_file.write(key)
    print(f"--- INFO: New encryption key generated and saved to '{KEY_FILE}'. ---")
    print("--- Secure this file, as all passwords depend on it! ---")
    return key

def load_key():
    """Loads the encryption key from the KEY_FILE or generates a new one."""
    try:
        if os.path.exists(KEY_FILE):
            with open(KEY_FILE, "rb") as key_file:
                return key_file.read()
        else:
            return generate_key_and_save()
    except Exception as e:
        print(f"ERROR: Could not load or generate key: {e}")
        exit()

# Load the key 
ENCRYPTION_KEY = load_key()
FERNET = Fernet(ENCRYPTION_KEY)

# --- Database Functions ---

def connect_db():
    """Establishes a connection to the MySQL database."""
    try:
        db = mysql.connector.connect(**DB_CONFIG)
        return db
    except mysql.connector.Error as err:
        print(f"Error connecting to MySQL: {err}")
        print("Please check your DB_CONFIG credentials and ensure the MySQL server is running.")
        return None

def create_table(db):
    """Creates the passwords table if it doesn't already exist."""
    cursor = db.cursor()
    table_name = "passwords"
    try:
        cursor.execute(f"""
            CREATE TABLE IF NOT EXISTS {table_name} (
                id INT AUTO_INCREMENT PRIMARY KEY,
                service VARCHAR(255) NOT NULL,
                username VARCHAR(255) NOT NULL,
                encrypted_password TEXT NOT NULL
            )
        """)
        db.commit()
        # print(f"Table '{table_name}' checked/created successfully.")
    except mysql.connector.Error as err:
        print(f"Error creating table: {err}")
    finally:
        cursor.close()

def reset_database(db):
    """Drops the passwords table and recreates it. DANGER: Deletes all data."""
    #confirmation
    choice = input("WARNING: This will delete ALL stored passwords. Type 'YES' to confirm: ").strip()
    if choice != 'YES':
        print("[INFO] Database reset aborted.")
        return

    cursor = db.cursor()
    table_name = "passwords"

    try:
        print(f"[INFO] Dropping table '{table_name}'...")
        cursor.execute(f"DROP TABLE IF EXISTS {table_name}")
        db.commit()
        print("[SUCCESS] Table dropped.")

        # Recreate the table 
        create_table(db)
        print("[SUCCESS] Database reset complete.")

    except mysql.connector.Error as err:
        print(f"[ERROR] Failed to reset database: {err}")
    finally:
        cursor.close()


# --- Manager Logic Functions ---

def add_password(db):
    """Prompts user for service, username, and password, then encrypts and saves it."""
    service = input("Enter Service Name (e.g., Google, Amazon): ").strip()
    username = input("Enter Username/Email: ").strip()
    password = getpass.getpass("Enter Password: ").strip()

    if not all([service, username, password]):
        print("All fields are required.")
        return

    # 1. Encrypt the password
    try:
        encrypted_password = FERNET.encrypt(password.encode()).decode()
    except Exception as e:
        print(f"Encryption failed: {e}")
        return

    # 2. Store the encrypted data in the database
    cursor = db.cursor()
    sql = "INSERT INTO passwords (service, username, encrypted_password) VALUES (%s, %s, %s)"
    val = (service, username, encrypted_password)

    try:
        cursor.execute(sql, val)
        db.commit()
        print(f"\n[SUCCESS] Password for '{service}' added successfully.")
    except mysql.connector.Error as err:
        print(f"\n[ERROR] Failed to add password: {err}")
    finally:
        cursor.close()
def generate_password(db):
    service = input("Enter Service Name (e.g., Google, Amazon): ").strip()
    username = input("Enter Username/Email: ").strip()
    password = getpass.getpass("Enter Password: ").strip()

    if not all([service, username, password]):
        print("All fields are required.")
        return

    # 1. Encrypt the password
    try:
        encrypted_password = FERNET.encrypt(password.encode()).decode()
    except Exception as e:
        print(f"Encryption failed: {e}")
        return

    # 2. Store the encrypted data in the database
    cursor = db.cursor()
    sql = "INSERT INTO passwords (service, username, encrypted_password) VALUES (%s, %s, %s)"
    val = (service, username, encrypted_password)

    try:
        cursor.execute(sql, val)
        db.commit()
        print(f"\n[SUCCESS] Password for '{service}' added successfully.")
    except mysql.connector.Error as err:
        print(f"\n[ERROR] Failed to add password: {err}")
    finally:
        cursor.close()

def get_password(db):
    """Prompts user for a service and retrieves all matching username-password pairs."""
    service = input("Enter Service Name to retrieve: ").strip()
    if not service:
        print("Service name cannot be empty.")
        return

    
    cursor = db.cursor(buffered=True)
    sql = "SELECT username, encrypted_password FROM passwords WHERE service = %s"
    val = (service,)

    try:
        cursor.execute(sql, val)
        results = cursor.fetchall()  

        if results:
            print(f"\n--- Details for '{service}' ---")
            for idx, (username, encrypted_password) in enumerate(results, start=1):
                try:
                    decrypted_password = FERNET.decrypt(encrypted_password.encode()).decode()
                except Exception:
                    decrypted_password = "[Decryption Failed – Wrong Key or Corrupted Data]"
                
                print(f"{idx}. Username: {username}")
                print(f"   Password: {decrypted_password}")
                print("-------------------------------")
        else:
            print(f"\n[INFO] No password found for service: '{service}'.")
    except mysql.connector.Error as err:
        print(f"\n[ERROR] Failed to retrieve password: {err}")
    finally:
        cursor.close()

def list_services(db):
    """Displays a list of all service names stored in the database."""
    cursor = db.cursor()
    sql = "SELECT DISTINCT service FROM passwords ORDER BY service"

    try:
        cursor.execute(sql)
        services = cursor.fetchall()
        
        if services:
            print("\n--- Stored Services ---")
            for i, (service,) in enumerate(services):
                print(f"{i+1}. {service}")
            print("-----------------------\n")
        else:
            print("\n[INFO] No services stored yet.")
            
    except mysql.connector.Error as err:
        print(f"\n[ERROR] Failed to list services: {err}")
    finally:
        cursor.close()

def main():
    """Main application loop."""
    print("--- Python/MySQL Secure Password Manager ---")

    db = connect_db()
    if not db:
        return

    # create the database table
    create_table(db)

    while True:
        print("\nWhat would you like to do?")
        print("1: Add New Password")
        print("2: Get Password")
        print("3: List Services")
        print("4: Quit")
        print("5: Reset Database (DANGER: Deletes all data!)")
        print("6: Generate Password : ")
        choice = input("Enter choice (1-6): ").strip()

        if choice == '1':
            add_password(db)
        elif choice == '2':
            get_password(db)
        elif choice == '3':
            list_services(db)
        elif choice == '4':
            print("Exiting Password Manager. Goodbye!")
            break
        elif choice == '5':
            reset_database(db)
        elif choice == '6':
            generate_password(db)
        else:
            print("Invalid choice. Please enter a number between 1 and 5.")

    if db.is_connected():
        db.close()
        # print("MySQL connection closed.")

if __name__ == "__main__":
    main()
