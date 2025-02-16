from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from flask_bcrypt import Bcrypt
import datetime
#from functools import wraps
from model import db, User
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt, get_jwt_identity

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI']='sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_secret_key'

db.init_app(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

jwt_blocklist = set()

with app.app_context():
    db.create_all()


#Load user from the file
# try:
#     with open('users.json') as file:
#         users = json.load(file)
# except FileNotFoundError:
#     users = {}

#Define the Token Required Decorator
# def token_required(f):
#     @wraps(f)
#     def decorated(*args, **kwargs):
#         token = request.headers.get('Authorization')

#         if not token:
#             return jsonify({'message': 'Token is missing'}), 401

#         parts = token.split(' ')
#         if len(parts) != 2 or parts[0] != 'Bearer':
#             return jsonify({'message': 'Invalid token format! Expected: Bearer <token>'}), 401

#         try:
#             token = parts[1]  # Extract token from "Bearer <token>"
#             data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
#             current_user = data['username']
#         except jwt.ExpiredSignatureError:
#             return jsonify({'message': 'Token is expired'}), 401
#         except jwt.InvalidTokenError:
#             return jsonify({'message': 'Token is invalid!'}), 401

#         return f(current_user, *args, **kwargs)
#     return decorated


# USER REGISTRATION
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if User.query.filter_by(username=username).first():
        return jsonify({'message': 'User already exists'}), 400
    
    #Hash the password before starting it
    hash_password = bcrypt.generate_password_hash(password).decode('utf-8')
    
    # users[username] = hash_password

    new_user = User(username=username, password=hash_password)
    db.session.add(new_user)
    db.session.commit()

    # with open('users.json', 'w') as file:
    #     json.dump(users, file, indent=4)

    return jsonify({'message': 'User created successfully'}), 201

#USER LOGIN
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    #Get stored hashed password
    #stored_hashed_password = users[username]
    user = User.query.filter_by(username=username).first()

    #Check if the user exists
    if user and bcrypt.check_password_hash(user.password, password):
        access_token = create_access_token(identity=username)
        return jsonify({'access_token': access_token}), 200
    else:
        return jsonify({'message': 'Invalid username or password'}), 401
    
    # #Generate JWT token
    # token = jwt.encode(
    #     {'username': username, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)},
    #     app.config['SECRET_KEY'],
    #     algorithm='HS256'
    # )

    #Verify the password
    # if not check_password_hash(stored_hashed_password, password):
    #     return jsonify({'message': 'Invalid username or password'}), 401
        # Decode token to string if needed (for Python 3.12+)
    # if isinstance(token, bytes):
    #     token = token.decode('utf-8')

    # return jsonify({'token': token})

@app.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    jti = get_jwt()['jti']
    jwt_blocklist.add(jti)
    # Invalidate the token (for simplicity, we'll just return a message)
    return jsonify({'message': 'Successfully logged out'}), 200


# Protect a Route using JWT
@app.route('/protected', methods=['GET'])
@jwt_required()
def protected_route():
    current_user = get_jwt_identity()
    return jsonify({'message': f'Hello {current_user}! This is a protected route.'})

@jwt.token_in_blocklist_loader
def check_if_token_is_revoked(jwt_header, jwt_payload):
    return jwt_payload['jti'] in jwt_blocklist  

#SHOW ALL USERS
@app.route('/users', methods=['GET'])
def get_users():
    users = User.query.all()
    return jsonify([{'id': user.id, 'username':user.username, 'password': user.password} for user in users])

if __name__ == '__main__':
    app.run(debug=True)



                        