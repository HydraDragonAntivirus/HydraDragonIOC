import yara
import os

# Get current working directory
script_dir = os.getcwd()

rule_file = os.path.join(script_dir, 'yararule', 'HackToolPythonPyramid.yar')
payloads_file = os.path.join(script_dir, 'payloads', 'onemorestepleft.py')
# Hardcoded path for the Yara rule file
rule_file = os.path.join(script_dir, 'yararules', 'HackToolPythonPyramid.yar')

# Prompt the user to input the payload file path
payloads_file_input = input(f"Enter the path to the payload file (relative to {script_dir}): ")

# Combine user input with the current working directory for payload file
payloads_file = os.path.join(script_dir, payloads_file_input)

# Load Yara rule
try:
    rules = yara.compile(filepath=rule_file)
except yara.YaraSyntaxError as e:
    print(f"Error compiling Yara rule: {e}")
    exit(1)

# Check if the payload file exists
if os.path.exists(payloads_file):
    print(f"Scanning started for: {payloads_file}")
    
    # Scan the file
    matches = rules.match(payloads_file)
    
    # If there are any matches
    if matches:
        print(f"Matches found in {payloads_file}:")
        for match in matches:
            print(f"Rule: {match.rule}")
            for string in match.strings:
                print(f"Matched string: {string}")
    else:
        print("No matches found.")
else:
    print(f"File not found: {payloads_file}")
