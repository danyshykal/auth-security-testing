"""
Run the auth API on http://127.0.0.1:5000 so you can explore it by hand (Postman, curl).

    python run_server.py               # secure mode
    python run_server.py --vulnerable  # flaws switched on

The automated tests do NOT need this: they start their own server.
"""
import sys

from app.auth_app import create_app

if __name__ == "__main__":
    vulnerable = "--vulnerable" in sys.argv
    print(f"Starting auth API in {'VULNERABLE' if vulnerable else 'secure'} mode on http://127.0.0.1:5000")
    create_app(vulnerable=vulnerable).run(host="127.0.0.1", port=5000)
