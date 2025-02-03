import json
from flask import Flask, request, jsonify

app = Flask(__name__)

#Load user from the file
with open('users.json') as file:
    users = json.load(file)

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if username in users:
        return jsonify({'message': 'User already exists'}), 400
    
    users[username] = password

    with open('users.json', 'w') as file:
        json.dump(users, file, indent=4)

    return jsonify({'message': 'User created successfully'}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if users.get(username) == password:
        return jsonify({'message': 'Login successful'}), 200
    
    else:
        return jsonify({'message': 'Invalid credentials'}), 401
    
if __name__ == '__main__':
    app.run(debug=True)
                        