#!/usr/bin/env python3
"""
Demo file with various security issues for ts-sast testing
"""

import ast
import operator
import os
import subprocess
import pickle
import yaml
import hashlib
import requests

# Safe operators for expression evaluation
_SAFE_OPERATORS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.FloorDiv: operator.floordiv,
    ast.Mod: operator.mod,
    ast.Pow: operator.pow,
    ast.USub: operator.neg,
    ast.UAdd: operator.pos,
    ast.Eq: operator.eq,
    ast.NotEq: operator.ne,
    ast.Lt: operator.lt,
    ast.LtE: operator.le,
    ast.Gt: operator.gt,
    ast.GtE: operator.ge,
}

def _safe_eval(node):
    """Safely evaluate an AST node with restricted operations."""
    if isinstance(node, ast.Constant):
        return node.value
    elif isinstance(node, ast.Num):  # For Python < 3.8 compatibility
        return node.n
    elif isinstance(node, ast.BinOp):
        left = _safe_eval(node.left)
        right = _safe_eval(node.right)
        op = _SAFE_OPERATORS.get(type(node.op))
        if op is None:
            raise ValueError(f"Unsupported operation: {type(node.op).__name__}")
        return op(left, right)
    elif isinstance(node, ast.UnaryOp):
        operand = _safe_eval(node.operand)
        op = _SAFE_OPERATORS.get(type(node.op))
        if op is None:
            raise ValueError(f"Unsupported operation: {type(node.op).__name__}")
        return op(operand)
    elif isinstance(node, ast.Compare):
        left = _safe_eval(node.left)
        for op, comparator in zip(node.ops, node.comparators):
            right = _safe_eval(comparator)
            op_func = _SAFE_OPERATORS.get(type(op))
            if op_func is None:
                raise ValueError(f"Unsupported operation: {type(op).__name__}")
            if not op_func(left, right):
                return False
            left = right
        return True
    elif isinstance(node, ast.Expression):
        return _safe_eval(node.body)
    else:
        raise ValueError(f"Unsupported expression: {type(node).__name__}")

# PY.EVAL.USE - Dangerous eval usage
def dangerous_eval(user_input):
    # FIXED: Use safe expression evaluation instead of eval()
    # Parse the input and evaluate with restricted operations only
    try:
        parsed = ast.parse(user_input, mode='eval')
        result = _safe_eval(parsed)
        return result
    except (SyntaxError, ValueError) as e:
        raise ValueError(f"Invalid or unsafe expression: {e}")

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

# PY.PICKLE.LOAD - Unsafe pickle deserialization
def load_data(data):
    obj = pickle.loads(data)  # SECURITY ISSUE: Code execution via pickle
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

    pickle_data = b"arbitrary bytes"
    obj = load_data(pickle_data)

    password_hash = hash_password("mypassword")

    data = fetch_data("https://api.example.com/data")

if __name__ == "__main__":
    main()
