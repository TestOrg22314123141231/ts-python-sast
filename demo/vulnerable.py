#!/usr/bin/env python3
"""
Demo file with various security issues for ts-sast testing
"""

import os
import subprocess
import pickle
import io
import yaml
import hashlib
import requests

# PY.EVAL.USE - Dangerous eval usage
def dangerous_eval(user_input):
    result = eval(user_input)  # SECURITY ISSUE: Code injection
    return result

# PY.SUBPROCESS.SHELL - Shell injection
def run_command(filename):
    subprocess.run(f"ls -la {filename}", shell=True)  # SECURITY ISSUE: Command injection

# PY.OS.SYSTEM - OS system usage
def delete_file(filename):
    os.system(f"rm {filename}")  # SECURITY ISSUE: Command injection

# PY.YAML.UNSAFE_LOAD - Unsafe YAML loading
def load_config(config_data):
    config = yaml.load(config_data)  # SECURITY ISSUE: Code execution via YAML
    return config

# PY.PICKLE.LOAD - Fixed: Using restricted unpickler
class RestrictedUnpickler(pickle.Unpickler):
    """Restricted unpickler that only allows safe built-in types."""

    # Whitelist of safe classes that can be unpickled
    SAFE_CLASSES = {
        ('builtins', 'dict'),
        ('builtins', 'list'),
        ('builtins', 'tuple'),
        ('builtins', 'set'),
        ('builtins', 'frozenset'),
        ('builtins', 'str'),
        ('builtins', 'bytes'),
        ('builtins', 'bytearray'),
        ('builtins', 'int'),
        ('builtins', 'float'),
        ('builtins', 'bool'),
        ('builtins', 'complex'),
        ('builtins', 'NoneType'),
        ('__builtin__', 'dict'),  # Python 2 compatibility
        ('__builtin__', 'list'),
        ('__builtin__', 'tuple'),
        ('__builtin__', 'set'),
        ('__builtin__', 'frozenset'),
        ('__builtin__', 'str'),
        ('__builtin__', 'bytes'),
        ('__builtin__', 'int'),
        ('__builtin__', 'float'),
        ('__builtin__', 'bool'),
        ('__builtin__', 'complex'),
        ('__builtin__', 'NoneType'),
    }

    def find_class(self, module, name):
        """Only allow safe built-in classes to be unpickled."""
        if (module, name) in self.SAFE_CLASSES:
            return super().find_class(module, name)
        # Raise an exception for any non-whitelisted class
        raise pickle.UnpicklingError(
            f"Attempted to unpickle unsafe class: {module}.{name}"
        )


def load_data(data):
    """Safely deserialize pickle data by restricting allowed classes."""
    obj = RestrictedUnpickler(io.BytesIO(data)).load()
    return obj

# PY.HASH.WEAK - Weak cryptographic hash
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()  # SECURITY ISSUE: Weak hash

# PY.REQUESTS.VERIFY_FALSE - Disabled SSL verification
def fetch_data(url):
    response = requests.get(url, verify=False)  # SECURITY ISSUE: MITM vulnerability
    return response.text

# PY.SECRET.HARDCODED - Hardcoded secrets
API_KEY = "sk-1234567890abcdef"  # SECURITY ISSUE: Hardcoded secret
DATABASE_PASSWORD = "super_secret_password"  # SECURITY ISSUE: Hardcoded password

def main():
    # Demo usage (don't actually run this!)
    user_data = input("Enter some data: ")
    dangerous_eval(user_data)

    run_command("test.txt")
    delete_file("temp.log")

    yaml_data = "key: value"
    config = load_config(yaml_data)

    pickle_data = pickle.dumps({"key": "value"})
    obj = load_data(pickle_data)

    password_hash = hash_password("mypassword")

    data = fetch_data("https://api.example.com/data")

if __name__ == "__main__":
    main()
