# jwks_server

## Project 2 for CSCE3550. 

How to run:

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
3. Drag the files into a folder in your working directory
4. Open up a second terminal
5. Navigate to the correct directory (should be a directory inside of the working one. So a directory on the same level as app.py)
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
