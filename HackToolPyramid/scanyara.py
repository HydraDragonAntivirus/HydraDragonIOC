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

# Store matches for summary
match_results = []

# Function to scan a single file
def scan_file(file_path, file_index, total_files):
    print(f"Scanning file {file_index + 1} of {total_files}: {file_path}")
    matches = rules.match(file_path)
    if matches:
        # Append file and match details to results
        match_results.append({
            "file": file_path,
            "matches": matches
        })
        print(f"Match found in: {file_path}")
    else:
        print(f"No match in: {file_path}")

# Check if the path exists
if os.path.exists(payload_path):
    files_to_scan = []
    
    if os.path.isfile(payload_path):
        # If it's a single file, add it to the list
        files_to_scan.append(payload_path)
    elif os.path.isdir(payload_path):
        # If it's a directory, gather all files within it
        print(f"Scanning all files in directory: {payload_path}")
        for root, _, files in os.walk(payload_path):
            for file in files:
                files_to_scan.append(os.path.join(root, file))
    else:
        print(f"Invalid path: {payload_path}")
        exit(1)
    
    # Total number of files to scan
    total_files = len(files_to_scan)
    
    # Scan each file with progress
    for index, file_path in enumerate(files_to_scan):
        scan_file(file_path, index, total_files)
else:
    print(f"Path not found: {payload_path}")
    exit(1)

# Print summary of matches
if match_results:
    print("\nSummary of Matches:")
    for result in match_results:
        print(f"File: {result['file']}")
        for match in result["matches"]:
            print(f"  Rule: {match.rule}")
            for string in match.strings:
                print(f"    Matched string: {string}")
else:
    print("\nNo matches found in the scanned files.")
