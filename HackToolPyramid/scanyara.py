import yara
import os

# Get the current working directory
script_dir = os.getcwd()

# Hardcoded path for the Yara rule file
rule_file = os.path.join(script_dir, 'yararule', 'HackToolPythonPyramid.yar')

# Prompt the user to input the payload file or directory path
payload_input = input(f"Enter the path to the payload file or directory (relative to {script_dir}): ")

# Combine user input with the current working directory
payload_path = os.path.join(script_dir, payload_input)

# Load Yara rule
try:
    rules = yara.compile(filepath=rule_file)
except yara.SyntaxError as e:
    print(f"Error compiling Yara rule: {e}")
    exit(1)

# Function to scan a single file
def scan_file(file_path):
    print(f"Scanning started for: {file_path}")
    matches = rules.match(file_path)
    if matches:
        print(f"Matches found in {file_path}:")
        for match in matches:
            print(f"Rule: {match.rule}")
            for string in match.strings:
                print(f"Matched string: {string}")
    else:
        print(f"No matches found in {file_path}")

# Check if the path exists
if os.path.exists(payload_path):
    if os.path.isfile(payload_path):
        # If it's a file, scan it
        scan_file(payload_path)
    elif os.path.isdir(payload_path):
        # If it's a directory, scan all files within it
        print(f"Scanning all files in directory: {payload_path}")
        for root, _, files in os.walk(payload_path):
            for file in files:
                file_path = os.path.join(root, file)
                scan_file(file_path)
    else:
        print(f"Invalid path: {payload_path}")
else:
    print(f"Path not found: {payload_path}")
