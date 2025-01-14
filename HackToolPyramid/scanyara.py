import yara
import os

# Get current working directory
script_dir = os.getcwd()

# Path to Yara rule file and payloads file
rule_file = os.path.join(script_dir, 'yararule', 'HackToolPythonPyramid.yar')
payloads_file = os.path.join(script_dir, 'payloads', 'onemorestepleft.py')

# Load Yara rule
rules = yara.compile(filepath=rule_file)

# Check if the file exists
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
