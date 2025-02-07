import json
from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'

#Load user from the file
try:
    with open('users.json') as file:
        users = json.load(file)
except FileNotFoundError:
    users = {}

#Define the Token Required Decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')

        if not token:
            return jsonify({'message': 'Token is missing'}), 401

        parts = token.split(' ')
        if len(parts) != 2 or parts[0] != 'Bearer':
            return jsonify({'message': 'Invalid token format! Expected: Bearer <token>'}), 401

        try:
            token = parts[1]  # Extract token from "Bearer <token>"
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = data['username']
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token is expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)
    return decorated


# USER REGISTRATION
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if username in users:
        return jsonify({'message': 'User already exists'}), 400
    
    #Hash the password before starting it
    hash_password = generate_password_hash(password)
    users[username] = hash_password

    with open('users.json', 'w') as file:
        json.dump(users, file, indent=4)

    return jsonify({'message': 'User created successfully'}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    #Get stored hashed password
    stored_hashed_password = users[username]

    #Check if the user exists
    if not stored_hashed_password or not check_password_hash(stored_hashed_password, password):
        return jsonify({'message': 'Invalid username or password'}), 401
    
    #Generate JWT token
    token = jwt.encode(
        {'username': username, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)},
        app.config['SECRET_KEY'],
        algorithm='HS256'
    )

    #Verify the password
    # if not check_password_hash(stored_hashed_password, password):
    #     return jsonify({'message': 'Invalid username or password'}), 401
        # Decode token to string if needed (for Python 3.12+)
    if isinstance(token, bytes):
        token = token.decode('utf-8')

    return jsonify({'token': token})

# Protect a Route using JWT
@app.route('/protected', methods=['GET'])
@token_required
def protected_route(current_user):
    return jsonify({'message': f'Hello {current_user}! This is a protected route.'})
    
if __name__ == '__main__':
    app.run(debug=True)
                        