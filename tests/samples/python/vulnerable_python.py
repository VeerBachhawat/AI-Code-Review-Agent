import os
import pickle
import sqlite3
import subprocess

DB_PASSWORD = "SuperSecretPassword123!"


def process_user_input(user_input: str, user_id: str):
    # Vulnerability 1: eval()
    result = eval(user_input)

    # Vulnerability 2: SQL string concatenation
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE id = '" + user_id + "'"
    cursor.execute(query)

    # Vulnerability 3: Command injection via subprocess shell=True
    cmd = "ping -c 1 " + user_input
    subprocess.run(cmd, shell=True)

    # Vulnerability 4: Unsafe deserialization
    raw_data = bytes.fromhex(user_input)
    obj = pickle.loads(raw_data)

    return result
