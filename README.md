# jwks_server

## Project 2 for CSCE3550. 

Environment:

Language: Python 3.13.2

Frameworks/Libraries:

Flask (web framework)
PyJWT (JWT signing and verification)
cryptography (RSA key generation and serialization)
SQLite3 (built-in Python module for database)
pytest, pytest-cov, and coverage (testing and coverage)
flake8 (linting)
requests (used for test interactions if needed)

Tested On: macOS (should work on any OS with Python 3 support)


How to run:

Make sure you are in the correct working directory. If not cd to it.
1. Setup Virtual Environment: python3 -m venv venv (or python)
2. Activate it: source venv/bin/activate
3. Then run: pip install -r requirements.txt
4. Start the flask app: python app.py

This will start the app up. 

It should say something like:
'''
 * Serving Flask app 'app'
 * Debug mode: off
WARNING: This is a development server. Do not use it in a production deployment. Use a production WSGI server instead.
 * Running on all addresses (0.0.0.0)
 * Running on http://127.0.0.1:8080
 * Running on http://192.168.1.57:8080
Press CTRL+C to quit
'''

This means the app is up and running.

How to test it against test client?
1. Install this: https://github.com/jh125486/CSCE3550
2. Unzip it
3. Drag the files (go.mod, go.sum, main.go) into your working directory (inside jwks_server)
4. Open up a second terminal
5. Navigate to the correct directory
6. Run: go run main.go project2


How to check coverage?
1. Run: coverage run -m pytest test_app.py
2. View the coverage report by doing coverage report -m


This project was made with the help of AI. I have included the prompts for you below.

First I provided the instructions from Canvas. Then I asked the following:
- Here’s my current app.py from Project 1. Add SQLite support to my JWKS server. Create totally_not_my_privateKeys.db and the keys table using safe parameterized queries.
- On startup, check if the DB is empty. If so, insert one expired key and one valid key (1 hour expiry). Serialize them as PEM before saving.
- Update POST:/auth to read a key from the DB (expired or valid based on query param), sign a JWT, and return it.
- Implement GET:/.well-known/jwks.json to return all valid (non-expired) public keys as a JWKS response.
- Write pytest tests to confirm DB exists, JWT signing works (valid and expired), and JWKS returns correct keys.

I made use of Co-Pilot (Claude Haiku 4.5) for this assignment. It was able to access my repo since its in GitHub and so it had the full context of all my previous files. I did not have to upload them. It was able to respond with code very fast and I was able to test it and fix any errors it made, which suprisingly was very little. I double checked the work myself and also used other AI to cross check its work. 
