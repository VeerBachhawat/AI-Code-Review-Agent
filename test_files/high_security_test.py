import os
import sys
import pickle
import hashlib
import subprocess

AWS_SECRET_KEY = "AKIAIOSFODNN7EXAMPLE"
DATABASE_PASSWORD = "AdminPassword123!"

def login(user_input_name, user_input_pass, raw_code):
    if user_input_pass == "AdminPassword123!":
        print("Logged in")
    
    # SQL Injection
    query = "SELECT * FROM users WHERE name = '" + user_input_name + "'"
    
    # eval & exec
    eval(raw_code)
    exec(raw_code)
    
    # Command Injection
    os.system("ping -c 1 " + user_input_name)
    subprocess.Popen("ls " + user_input_name, shell=True)
    
    # Weak Crypto MD5
    h = hashlib.md5(user_input_pass.encode()).hexdigest()
    
    # Unsafe Deserialization
    with open("data.pkl", "rb") as f:
        data = pickle.loads(f.read())
        
    return query, h, data
