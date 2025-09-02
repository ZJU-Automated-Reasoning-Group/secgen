"""
Test file containing various Python vulnerabilities for SecGen testing.
"""

import os
import subprocess
import sqlite3
import pickle
import sys


# SQL Injection vulnerability
def sql_injection_example(user_id):
    """Vulnerable SQL query construction."""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # Dangerous - user input directly in SQL query
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)  # SQL injection vulnerability
    
    results = cursor.fetchall()
    conn.close()
    return results


# Command injection vulnerability
def command_injection_example(filename):
    """Vulnerable system command execution."""
    # Dangerous - user input directly in system command
    command = f"cat {filename}"
    result = os.system(command)  # Command injection vulnerability
    return result


# Another command injection example
def subprocess_injection_example(user_input):
    """Vulnerable subprocess call."""
    # Dangerous - shell=True with user input
    result = subprocess.run(f"echo {user_input}", shell=True, capture_output=True)
    return result.stdout


# Insecure deserialization
def pickle_deserialization_example(data):
    """Vulnerable pickle deserialization."""
    # Dangerous - deserializing untrusted data
    obj = pickle.loads(data)  # Insecure deserialization vulnerability
    return obj


# Code injection via eval
def eval_injection_example(user_expression):
    """Vulnerable eval usage."""
    # Dangerous - evaluating user input as code
    result = eval(user_expression)  # Code injection vulnerability
    return result


# Code injection via exec
def exec_injection_example(user_code):
    """Vulnerable exec usage."""
    # Dangerous - executing user input as code
    exec(user_code)  # Code injection vulnerability


# Path traversal vulnerability
def path_traversal_example(filename):
    """Vulnerable file access."""
    # Dangerous - no path validation
    file_path = f"uploads/{filename}"
    
    try:
        with open(file_path, 'r') as f:  # Path traversal vulnerability
            content = f.read()
        return content
    except FileNotFoundError:
        return "File not found"


# Hardcoded credentials (bad practice)
def hardcoded_credentials_example():
    """Example with hardcoded credentials."""
    # Bad - hardcoded credentials
    database_password = "super_secret_password123"  # Hardcoded credential
    api_key = "sk-1234567890abcdef"  # Hardcoded API key
    
    return database_password, api_key


# Weak random number generation
def weak_random_example():
    """Weak random number generation."""
    import random
    
    # Weak - predictable random numbers for security purposes
    session_token = str(random.randint(1000000, 9999999))  # Weak randomness
    return session_token


# Information disclosure in logs
def information_disclosure_example(user_data):
    """Information disclosure through logging."""
    username = user_data.get('username')
    password = user_data.get('password')
    
    # Dangerous - logging sensitive information
    print(f"Login attempt: username={username}, password={password}")  # Info disclosure
    
    return username


# XSS vulnerability (in web context)
def xss_vulnerability_example(user_comment):
    """XSS vulnerability in template rendering."""
    # In a real web app, this would be dangerous
    html_output = f"<div>User comment: {user_comment}</div>"  # Potential XSS
    return html_output


# LDAP injection vulnerability
def ldap_injection_example(username):
    """LDAP injection vulnerability."""
    # Dangerous - user input directly in LDAP query
    ldap_query = f"(&(objectClass=user)(cn={username}))"  # LDAP injection
    return ldap_query


# XML injection vulnerability
def xml_injection_example(user_data):
    """XML injection vulnerability."""
    # Dangerous - user input directly in XML
    xml_content = f"<user><name>{user_data}</name></user>"  # XML injection
    return xml_content


# Unsafe YAML loading
def yaml_injection_example(yaml_data):
    """YAML injection vulnerability."""
    import yaml
    
    # Dangerous - unsafe YAML loading
    data = yaml.load(yaml_data)  # Should use yaml.safe_load()
    return data


# Template injection
def template_injection_example(user_template):
    """Template injection vulnerability."""
    from string import Template
    
    # Dangerous - user-controlled template
    template = Template(user_template)
    result = template.substitute(name="World")  # Template injection
    return result


def main():
    """Main function demonstrating vulnerable patterns."""
    print("SecGen Python Vulnerability Test Suite")
    print("This file contains intentional vulnerabilities for testing")
    
    # These would trigger vulnerabilities in a real application
    # sql_injection_example("1 OR 1=1")
    # command_injection_example("file.txt; rm -rf /")
    # subprocess_injection_example("hello; cat /etc/passwd")
    # eval_injection_example("__import__('os').system('ls')")
    # path_traversal_example("../../../etc/passwd")
    
    print("Test completed")


if __name__ == "__main__":
    main()
