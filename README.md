# cardbox-auth

## Overview
`cardbox-auth` is a Python project that utilizes FastAPI for building API for jwt authentication. It includes configurations managed by Pydantic and environment variables stored in a `.env` file.

## Requirements
- Python 3.11+

## Installation
1. Clone the repository:
    ```sh
    git clone <repository_url>
    cd cardbox-auth
    ```

2. Create a virtual environment:
    ```sh
    python -m venv venv
    source venv/bin/activate  # On Windows use `venv\Scripts\activate`
    ```

3. Install the dependencies:
    ```sh
    pip install -r requirements.txt
    ```

## Configuration
The project uses environment variables for configuration. Create a `.env` file in the root directory with the content from .env.sample file.

## Usage

1. Run the FastAPI application:

   ```bash
   uvicorn main:app --reload
   
2. Open the API documentation in your browser:

   ```
   http://127.0.0.1:8000/docs#/
   ```