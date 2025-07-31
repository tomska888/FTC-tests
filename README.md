# Scanner Toolkit

Runs five FTC checks (URL reputation, headers, geo, DNS) and writes results to a file.

## Setup

1. Create & activate a venv:
   ```bash
   python -m venv .venv 
   (or python3)
   .venv\Scripts\Activate.ps1
    ```
2. Install deps
    ```bash
    pip install --upgrade pip
    pip install -r requirements.txt
    ```

3. Usage
    ```bash
    python -m scanner.main https://example.com
    python -m scanner.main example.com
    python -m scanner.main www.example.com
    ```
