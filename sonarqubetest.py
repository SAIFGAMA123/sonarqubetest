import os
import sys
import re
import logging
import hashlib
import requests
from datetime import datetime

# Insecure Password storage
def insecure_password_storage(password):
    hashed_password = hashlib.md5(password.encode()).hexdigest()  # MD5 is weak
    return hashed_password

# Command Injection vulnerability
def run_command(command):
    os.system(command)  # Insecure system command execution

# Cross-Site Scripting (XSS)
def xss_vulnerability(input_data):
    print(f"Hello {input_data}")  # Vulnerable to XSS if input_data contains malicious script

# Insecure file upload (accepting any file type)
def insecure_file_upload(file_path):
    with open(file_path, 'r') as file:
        content = file.read()  # File content being processed without any validation

# SQL Injection vulnerability
def sql_injection(user_input):
    query = f"SELECT * FROM users WHERE username = '{user_input}'"
    result = execute_query(query)  # Executes query without sanitization

# Hardcoded sensitive data
API_KEY = "1234567890abcdef"  # Hardcoded API Key, a security risk

# Logging sensitive information
def log_sensitive_data(data):
    logging.basicConfig(level=logging.DEBUG)
    logging.debug(f"Sensitive data: {data}")  # Logging sensitive information

# Infinite loop bug
def infinite_loop():
    while True:
        pass  # This will cause the program to enter an infinite loop

# Uncaught exception bug
def divide_by_zero():
    try:
        return 1 / 0
    except ZeroDivisionError:
        pass  # Exception swallowed

# Insecure deserialization (loading untrusted data)
import pickle
def insecure_deserialization(serialized_data):
    data = pickle.loads(serialized_data)  # Can lead to code execution vulnerabilities

# File path traversal vulnerability
def path_traversal(vulnerable_path):
    with open(vulnerable_path, 'r') as file:
        print(file.read())  # Allows reading files outside the intended directory

# Improper access control
class User:
    def __init__(self, username, password):
        self.username = username
        self.password = password

def check_access(user):
    if user.username == "admin":
        return True
    else:
        return False  # Insufficient access control, allows unauthorized access

# Unencrypted communication (HTTP instead of HTTPS)
def send_request():
    response = requests.get('http://example.com')  # No encryption used

# Insecure random number generation
def insecure_random():
    return random.randint(0, 100)  # Predictable random number generation, can be insecure

# Weak password policy
def weak_password_check(password):
    if len(password) < 8:
        print("Password is too weak!")  # No strong password enforcement

# Unvalidated redirect
def unvalidated_redirect(url):
    if url:
        print(f"Redirecting to {url}")  # No validation of the URL before redirecting

# Resource leak (File not closed properly)
def resource_leak():
    file = open("large_file.txt", 'r')
    content = file.read()  # File is not closed, causing resource leakage

# Unsafe use of eval
def unsafe_eval(data):
    eval(data)  # Unsafe eval execution, can lead to code injection

# Incorrect exception handling
def wrong_exception_handling():
    try:
        int("abc")  # Will raise ValueError
    except TypeError:  # Incorrect exception handling, TypeError is not the issue
        pass

# Lack of input validation (file name input)
def input_validation(file_name):
    if file_name:
        with open(file_name, 'r') as file:
            print(file.read())  # No validation on the input file name

# Buffer overflow vulnerability
def buffer_overflow():
    arr = [0] * 10
    arr[100] = 5  # Buffer overflow, out of bounds access

# Use of outdated libraries
import urllib2  # Deprecated in Python 3.x
def outdated_library_usage():
    response = urllib2.urlopen('http://example.com')  # Use of outdated library

# Improper error handling
def improper_error_handling():
    try:
        return 1 / 0  # Division by zero
    except Exception as e:
        print("Something went wrong!")  # Generic exception message, no details

# Weak hash function
def weak_hash_function(data):
    return hashlib.sha1(data.encode()).hexdigest()  # SHA-1 is weak

# Insecure use of SSL/TLS
import ssl
def insecure_ssl_connection():
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # Insecure SSL/TLS usage, no certificate verification

# Inefficient sorting algorithm
def inefficient_sort(arr):
    for i in range(len(arr)):
        for j in range(len(arr) - 1):
            if arr[j] > arr[j + 1]:
                arr[j], arr[j + 1] = arr[j + 1], arr[j]  # Inefficient sorting algorithm (Bubble Sort)

# Failure to sanitize inputs (file name)
def unsanitized_input(input_data):
    print(f"Received input: {input_data}")  # No sanitization of input

# Insecure use of subprocess
import subprocess
def insecure_subprocess():
    subprocess.run("rm -rf /", shell=True)  # Dangerous command, potential for misuse

# Use of deprecated functions
import urllib
def deprecated_function_usage():
    urllib.urlopen('http://example.com')  # Deprecated function in Python 3.x

# Memory leak (not releasing memory)
def memory_leak():
    data = []
    while True:
        data.append("Some data")  # Continually adding to the list, causing memory leak

# Inefficient database query
def inefficient_query():
    query = "SELECT * FROM users WHERE age > 20"
    result = execute_query(query)  # Inefficient query, should be optimized

# Use of unsafe string formatting
def unsafe_string_formatting():
    user_input = "123"
    print("Hello, %s" % user_input)  # Vulnerable to format string vulnerabilities

if __name__ == "__main__":
    # Example function calls to trigger vulnerabilities
    insecure_password_storage("password")
    run_command("rm -rf /")
    xss_vulnerability("<script>alert('XSS')</script>")
    sql_injection("' OR '1'='1")
    insecure_file_upload("example.txt")
    path_traversal("../../etc/passwd")
    send_request()
    insecure_random()
    weak_password_check("12345")
    unvalidated_redirect("http://malicious.com")
    resource_leak()
    unsafe_eval("__import__('os').system('rm -rf /')")
    wrong_exception_handling()
    input_validation("example.txt")
    buffer_overflow()
    outdated_library_usage()
    improper_error_handling()
    weak_hash_function("data")
    insecure_ssl_connection()
    inefficient_sort([5, 3, 8, 6, 7])
    unsanitized_input("<script>")
    insecure_subprocess()
    deprecated_function_usage()
    memory_leak()
    inefficient_query()
    unsafe_string_formatting()

