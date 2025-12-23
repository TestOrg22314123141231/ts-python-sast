#!/usr/bin/env python3
"""
Demo file with various security issues for ts-sast testing
"""

import os
import subprocess
import pickle
import yaml
import hashlib
import requests
import ast
import operator

# PY.EVAL.USE - Dangerous eval usage
def dangerous_eval(user_input):
    # Fixed: Safe expression evaluator that handles arithmetic and literals
    # but prevents arbitrary code execution
    allowed_nodes = (
        ast.Expression, ast.Constant, ast.Num, ast.Str, ast.Bytes,
        ast.List, ast.Tuple, ast.Set, ast.Dict,
        ast.BinOp, ast.UnaryOp, ast.Compare,
        ast.Add, ast.Sub, ast.Mult, ast.Div, ast.FloorDiv, ast.Mod, ast.Pow,
        ast.USub, ast.UAdd,
        ast.Eq, ast.NotEq, ast.Lt, ast.LtE, ast.Gt, ast.GtE,
        ast.And, ast.Or, ast.Not, ast.BoolOp,
    )

    allowed_operators = {
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

    def safe_eval_node(node):
        if isinstance(node, ast.Constant):
            return node.value
        elif isinstance(node, ast.Num):  # Python < 3.8 compatibility
            return node.n
        elif isinstance(node, ast.Str):  # Python < 3.8 compatibility
            return node.s
        elif isinstance(node, ast.Bytes):
            return node.s
        elif isinstance(node, ast.List):
            return [safe_eval_node(item) for item in node.elts]
        elif isinstance(node, ast.Tuple):
            return tuple(safe_eval_node(item) for item in node.elts)
        elif isinstance(node, ast.Set):
            return {safe_eval_node(item) for item in node.elts}
        elif isinstance(node, ast.Dict):
            return {safe_eval_node(k): safe_eval_node(v) for k, v in zip(node.keys, node.values)}
        elif isinstance(node, ast.BinOp):
            left = safe_eval_node(node.left)
            right = safe_eval_node(node.right)
            op = allowed_operators.get(type(node.op))
            if op:
                return op(left, right)
            raise ValueError(f"Unsupported binary operator: {type(node.op).__name__}")
        elif isinstance(node, ast.UnaryOp):
            operand = safe_eval_node(node.operand)
            op = allowed_operators.get(type(node.op))
            if op:
                return op(operand)
            raise ValueError(f"Unsupported unary operator: {type(node.op).__name__}")
        elif isinstance(node, ast.Compare):
            left = safe_eval_node(node.left)
            for op, comparator in zip(node.ops, node.comparators):
                right = safe_eval_node(comparator)
                op_func = allowed_operators.get(type(op))
                if not op_func:
                    raise ValueError(f"Unsupported comparison operator: {type(op).__name__}")
                if not op_func(left, right):
                    return False
                left = right
            return True
        elif isinstance(node, ast.BoolOp):
            values = [safe_eval_node(v) for v in node.values]
            if isinstance(node.op, ast.And):
                return all(values)
            elif isinstance(node.op, ast.Or):
                return any(values)
            raise ValueError(f"Unsupported boolean operator: {type(node.op).__name__}")
        else:
            raise ValueError(f"Unsafe expression: {type(node).__name__}")

    try:
        parsed = ast.parse(user_input, mode='eval')
        # Verify all nodes are allowed
        for node in ast.walk(parsed):
            if not isinstance(node, allowed_nodes):
                raise ValueError(f"Unsafe node type: {type(node).__name__}")
        result = safe_eval_node(parsed.body)
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
