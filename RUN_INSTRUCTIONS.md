# How to Run the Steganography Detector Project

This document provides step-by-step instructions to set up and run the **Steganography Detector** (Forensic Image Analysis Tool) web application on your local machine.

---

## 🛠️ Prerequisites

Before you begin, ensure you have the following installed:
* **Python 3.8 or higher**: You can download it from the [Official Python Website](https://www.python.org/downloads/).
  > [!IMPORTANT]
  > During installation on Windows, make sure to check the box that says **"Add Python to PATH"** (or **"Add python.exe to PATH"**). This ensures that you can run Python commands directly from your terminal.

---

## 🚀 Setup & Running Instructions

Choose the appropriate section below based on your operating system.

### 💻 Windows Setup (PowerShell & Command Prompt)

Follow these steps to run the application on Windows:

#### 1. Open Terminal and Navigate to the Project Folder
Open **PowerShell** or **Command Prompt** (CMD) and navigate to the project directory:
```powershell
cd "C:\Users\NIVETHA\OneDrive\Pictures\Mini project Antigrav"
```

#### 2. Create a Virtual Environment
It is highly recommended to run Python projects inside a virtual environment to avoid package conflicts:
```powershell
python -m venv venv
```
*(This creates a folder named `venv` in your project directory containing an isolated Python installation).*

#### 3. Activate the Virtual Environment
Activate the environment depending on the shell you are using:

* **If using PowerShell:**
  ```powershell
  .\venv\Scripts\Activate.ps1
  ```
  *(If you get a script execution policy error, see the **Troubleshooting** section below).*

* **If using Command Prompt (CMD):**
  ```cmd
  .\venv\Scripts\activate.bat
  ```

Once activated, your command line prompt will show `(venv)` at the beginning.

#### 4. Install Required Packages
Install the dependencies listed in `requirements.txt` (Flask and Pillow):
```powershell
pip install -r requirements.txt
```

#### 5. Start the Flask Server
Run the Flask application:
```powershell
python app.py
```
Upon running, you should see output indicating that the server is active on `http://127.0.0.1:5000/`.

#### 6. Open the Dashboard in Your Browser
Open your web browser and go to:
👉 **[http://127.0.0.1:5000/](http://127.0.0.1:5000/)**

---

### 🍎 macOS & Linux Setup

Follow these steps to run the application on macOS or Linux:

#### 1. Open Terminal and Navigate to the Project Folder
```bash
cd "/path/to/Mini project Antigrav"
```

#### 2. Create a Virtual Environment
```bash
python3 -m venv venv
```

#### 3. Activate the Virtual Environment
```bash
source venv/bin/activate
```
Once activated, your command line prompt will show `(venv)` at the beginning.

#### 4. Install Required Packages
```bash
pip install -r requirements.txt
```

#### 5. Start the Flask Server
```bash
python app.py
```
*(Alternatively, you can run `python3 app.py`).*

#### 6. Open the Dashboard in Your Browser
Open your web browser and go to:
👉 **[http://127.0.0.1:5000/](http://127.0.0.1:5000/)**

---

## 🔍 Troubleshooting

Here are solutions to common issues you might run into:

### ⚠️ Windows: Script Execution Policy Error
**Error:** `...\Activate.ps1 cannot be loaded because running scripts is disabled on this system.`
* **Solution 1:** You can run CMD (Command Prompt) instead and run `.\venv\Scripts\activate.bat`.
* **Solution 2 (PowerShell):** Run this command to bypass the restriction for the current PowerShell session only:
  ```powershell
  Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
  ```
  After running that, try activating the virtual environment again: `.\venv\Scripts\Activate.ps1`.

### ⚠️ Python command not found
**Error:** `'python' is not recognized as an internal or external command...`
* **Solution 1:** Make sure you installed Python and checked the **"Add Python to PATH"** checkbox.
* **Solution 2:** Try running `py` or `python3` instead of `python`:
  ```powershell
  py -m venv venv
  py app.py
  ```

### ⚠️ Port 5000 is already in use
**Error:** `OSError: [Errno 98] Address already in use` or similar port conflict errors.
* **Solution:** Open the [app.py](file:///C:/Users/NIVETHA/OneDrive/Pictures/Mini%20project%20Antigrav/app.py) file and locate the last line:
  ```python
  app.run(debug=True, port=5000)
  ```
  Change `port=5000` to a different number (e.g., `port=5001` or `port=8080`), save the file, and run `python app.py` again. You can then access the app at `http://127.0.0.1:5001/` (or the new port you specified).

---

## 🛑 How to Stop the App

To stop the Flask web server:
1. Press `Ctrl + C` in the terminal/command prompt window where the server is running.
2. To deactivate the virtual environment, run:
   ```bash
   deactivate
   ```
