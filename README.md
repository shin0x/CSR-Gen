# CSR-Generator

## Overview
The CSR-Generator is a web application built using Flask that allows users to generate Certificate Signing Requests (CSRs) for multiple domain names. The application provides an interface to input domain names and additional information required for the CSR. Users can also save their configuration settings in cookies for future use.

## Features
- Generate CSR for multiple domain names.
- Save and load configuration settings using cookies.
- Option to sert suffix for domain names.
- Advanced settings for additional CSR information.

## Installation

1. **Clone the repository:**
    ```sh
    git clone https://github.com/shin0x/CSR-Gen.git
    cd CSR-Gen
    ```

2. **Install the required packages:**
    ```sh
    pip install -r requirements.txt
    ```

3. **Run the application:**
    ```sh
    python csr-gen.py
    ```

4. **Open your browser and navigate to:**
    ```
    http://127.0.0.1:5000/
    ```

## Usage

1. **Enter the domain names:**
    - Input the domain names separated by commas in the provided text box.

2. **Advanced Settings:**
    - Click on the "Advanced Settings" button to expand additional fields.
    - Fill in the country, state, locality, organization, and organizational unit information.
    - Optionally, enter a suffix for the domain names.

3. **Save Configuration:**
    - Click the "Save Configuration" button to save the current settings in a cookie.

4. **Clear Configuration:**
    - Click the "Clear Configuration" button to clear the saved settings.

5. **Generate CSR:**
    - Click the "Generate CSR" button to generate the CSR and Key and download both as a zip file.

## File Structure

- `csr-gen.py`: Main Flask application file.
- `templates/index.html`: HTML template for the web interface.
- `info.json`: JSON file containing default configuration information.
- `requirements.txt`: List of Python packages required for the application.

## Dependencies

- Flask
- cryptography