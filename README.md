
# File Encryption and Monitoring System

## Summary

This project implements a file encryption and monitoring system that performs the following tasks:

1. **Encryption**: Encrypts files in a folder using AES encryption with a password-derived key.
2. **File Monitoring**: Monitors the folder for suspicious file modification activity.
3. **File Locking**: Locks files if suspicious activity exceeds a defined threshold.
4. **Report Generation**: Generates a PDF report of modified files when suspicious activity is detected.

This system is designed as part of an assignment for the CSCE-550 Introduction to Computer Security course.

---

## Files in the Project

### 1. `src/encryption.py`

This script encrypts files in a specified folder. Key features include:
- **AES Encryption**: Uses a secure encryption algorithm with a random IV.
- **Password-Based Key Derivation**: Utilizes the Scrypt algorithm to derive a key from a password.
- **Salt Storage**: Creates and saves a `salt.bin` file to enable future decryption.

### 2. `src/monitorandmitigate.py`

This script monitors a folder for suspicious activity, such as excessive file modifications, and performs the following actions:
- **File Monitoring**: Tracks file changes in the folder using the `watchdog` library.
- **File Locking**: Locks files using Windows-specific APIs if suspicious activity is detected.
- **Report Generation**: Generates a PDF report listing modified files and their modification times.

### 3. `.env`

A configuration file containing environment variables used by the scripts. Example:

```plaintext
FOLDER_PATH = "absolute_path_to_the_folder_to_encrypt_and_monitor"
SEND_GRID_API_KEY = "your_send_grid_api_key"
```

---

## Requirements

### Software Requirements
- Python 3.x
- Windows OS (required for file locking functionality)

---

## Steps to Set Up and Execute the Project

### 1. **Clone the Repository**
Clone the project repository from GitHub:
```bash
git clone https://github.com/sudinjoshi/csce-5550-ransomware-project.git
cd csce-5550-ransomware-project
```

### 2. **Install Dependencies**
Install all required Python libraries from the `requirements.txt` file:
```bash
pip install -r requirements.txt
```

### 3. **Configure the `.env` File**
Update the `.env` file with the absolute path to the folder to be encrypted/monitored:
```plaintext
FOLDER_PATH = "absolute_path_to_the_folder"
```

### 4. **Generate Executable Files**
Create standalone executable files for both `encryption.py` and `monitorandmitigate.py` using PyInstaller:
```bash
pyinstaller --onefile .\src\encryption.py
pyinstaller --onefile .\src\monitorandmitigate.py
```
The executable files will be generated inside the `dist` folder.

### 5. **Start the Monitoring System**
Run the `monitorandmitigate` executable to begin monitoring the folder:
```bash
.\dist\monitorandmitigate.exe
```
The program will launch, continuously monitoring the folder for suspicious activity. Keep this program running in the background.

### 6. **Run the Encryption Process**
Run the `encryption` executable to encrypt all files in the specified folder:
```bash
.\dist\encryption.exe
```
Observe the console for both programs. Once the encryption process completes:
- Encrypted files will replace the original files.
- A PDF report named `modified_files_report.pdf` will be generated if suspicious activity is detected.

---

## Outputs

1. **Encrypted Files**: Original files will be replaced by their encrypted versions.
2. **Salt File**: A `salt.bin` file will be saved in the folder for decryption.
3. **PDF Report**: If suspicious activity is detected, a `modified_files_report.pdf` will be generated, listing the modified files.

--- 

This completes the setup and execution process for the File Encryption and Monitoring System.
