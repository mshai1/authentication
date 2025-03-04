from flask import Flask, request, jsonify
from flask_migrate import Migrate
from flask_argon2 import Argon2
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import random
from flask_bcrypt import Bcrypt
from datetime import datetime, timedelta
#from functools import wraps
from model import db, User, App, UserApp
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt, get_jwt_identity

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI']='sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_TOKEN_EXPIRES'] = timedelta(hours=1)
app.config['SECRET_KEY'] = 'your_secret_key'

db.init_app(app)
migrate = Migrate(app, db)
argon2 = Argon2(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
jwt_blocklist = set()

with app.app_context():
    db.create_all()

        # Ensure CoffeeHub app exists
    if not App.query.filter_by(name='CoffeeHub').first():
        coffee_hub = App(name='CoffeeHub', app_id=random.randint(1000, 9999))  # Unique app_id
        db.session.add(coffee_hub)
        db.session.commit()
    
    # Assign all users to CoffeeHub with 'member' role
    coffee_hub = App.query.filter_by(name='CoffeeHub').first()
    for user in User.query.all():
        if not UserApp.query.filter_by(user_id=user.id, app_id=coffee_hub.id).first():
            db.session.add(UserApp(user_id=user.id, app_id=coffee_hub.id, role='member'))
    db.session.commit()

# USER REGISTRATION
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    role = data.get('role', 'user')  # Default role is 'user'

    if User.query.filter_by(username=username).first():
        return jsonify({'message': 'User already exists'}), 400
    
    #Hash the password before starting it
    hash_password = argon2.generate_password_hash(password)
    
    # users[username] = hash_password

    new_user = User(username=username, password=hash_password, role=role)
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
    if user and argon2.check_password_hash(user.password, password):
        access_token = create_access_token(identity=username)
        return jsonify({'access_token': access_token}), 200
    else:
        return jsonify({'message': 'Invalid username or password'}), 401
    

#LOGOUT
@app.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    jti = get_jwt()['jti']
    jwt_blocklist.add(jti)
    # Invalidate the token (for simplicity, we'll just return a message)
    return jsonify({'message': 'Successfully logged out'}), 200

#UPDATE USER PASSWORD
@app.route('/update-password', methods=['PUT'])
@jwt_required()
def update_password():
    current_user = get_jwt_identity()
    user = User.query.filter_by(username=current_user).first()

    if not user:
        return jsonify({'message': 'User not found'}), 404

    data = request.get_json()
    current_password = data.get('current_password')
    new_password = data.get('new_password')

    # Verify current password
    if not argon2.check_password_hash(user.password, current_password):
        return jsonify({'message': 'Incorrect current password'}), 400

    # Hash the new password
    hashed_password = argon2.generate_password_hash(new_password)
    user.password = hashed_password
    db.session.commit()

    return jsonify({'message': 'Password updated successfully'}), 200

# Protect a Route using JWT
@app.route('/protected', methods=['GET'])
@jwt_required()
def protected_route():
    current_user = get_jwt_identity()
    return jsonify({'message': f'Hello {current_user}! This is a protected route.'})

@jwt.token_in_blocklist_loader
def check_if_token_is_revoked(jwt_header, jwt_payload):
    return jwt_payload['jti'] in jwt_blocklist  


#Show all apps to superadmin and admin and require jwt token
@app.route('/apps', methods=['GET'])
@jwt_required()
def get_apps():
    current_user = get_jwt_identity()
    user = User.query.filter_by(username=current_user).first()

    if user.role == 'superadmin' or user.role == 'admin':
        apps = App.query.all()
    else:
        apps = [user_app.app for user_app in user.user_apps]

    return jsonify([
        {
            'id': app.id,
            'name': app.name,
            'app_id': app.app_id
        } 
        for app in apps
    ])


#Assign User to App
@app.route('/assign-app', methods=['POST'])
@jwt_required()
def assign_app():
    current_user = get_jwt_identity()
    user = User.query.filter_by(username=current_user).first()

    if not user:
        return jsonify({'message': 'User not found'}), 404

    data = request.get_json()
    username = data.get('username')
    app_name = data.get('app_name')
    access_level = data.get('access_level')

    user_to_assign = User.query.filter_by(username=username).first()
    app = App.query.filter_by(name=app_name).first()

    if not user_to_assign or not app:
        return jsonify({'message': 'User or app not found'}), 404
    
    if not access_level:
        return jsonify({'message': 'Access level cannot be empty'}), 400
    
    if UserApp.query.filter_by(user_id=user_to_assign.id, app_id=app.id).first():
        return jsonify({'message': 'User already assigned to this app'}), 400
    
    #Check if current user is superadmin
    if user.role != 'superadmin' and access_level == 'admin':
        return jsonify({'message': 'Access denied: Superadmins or Admin only'}), 403
    
    new_user_app = UserApp(user_id=user_to_assign.id, app_id=app.id, access_level=access_level)
    db.session.add(new_user_app)
    db.session.commit()
    return jsonify({'message': f'User {user.username} assigned to {app_name} with {access_level} access'}), 201

#Update User App Access Level
@app.route('/update-access-level', methods=['PATCH'])
@jwt_required()
def update_access_level():
    current_user = get_jwt_identity()
    user = User.query.filter_by(username=current_user).first()

    if not user:
        return jsonify({'message': 'User not found'}), 404

    data = request.get_json()
    username = data.get('username')
    app_name = data.get('app_name')
    new_access_level = data.get('new_access_level')

    user_to_update = User.query.filter_by(username=username).first()
    app = App.query.filter_by(name=app_name).first()

    if not user_to_update or not app:
        return jsonify({'message': 'User or app not found'}), 404
    
    if not new_access_level:
        return jsonify({'message': 'Access level cannot be empty'}), 400
    
    user_app = UserApp.query.filter_by(user_id=user_to_update.id, app_id=app.id).first()
    if not user_app:
        return jsonify({'message': 'User not assigned to this app'}), 404
    
    #Check if current user is superadmin
    if user.role != 'superadmin' or user.role != 'admin' or (user.role == 'admin' and new_access_level == 'admin'):
        return jsonify({'message': 'Access denied: Superadmins only'}), 403
    
    user_app.access_level = new_access_level
    db.session.commit()
    return jsonify({'message': f'User {user.username} access level to {app_name} updated to {new_access_level}'}), 200

#Update User App Status
@app.route('/update-status', methods=['PATCH'])
@jwt_required()
def update_status():
    current_user = get_jwt_identity()
    user = User.query.filter_by(username=current_user).first()

    if not user:
        return jsonify({'message': 'User not found'}), 404

    data = request.get_json()
    username = data.get('username')
    app_name = data.get('app_name')
    new_status = data.get('new_status')

    user_to_update = User.query.filter_by(username=username).first()
    app = App.query.filter_by(name=app_name).first()

    if not user_to_update or not app:
        return jsonify({'message': 'User or app not found'}), 404
    
    if not new_status:
        return jsonify({'message': 'Status cannot be empty'}), 400
    
    user_app = UserApp.query.filter_by(user_id=user_to_update.id, app_id=app.id).first()
    if not user_app:
        return jsonify({'message': 'User not assigned to this app'}), 404
    
    #Check if current user is superadmin
    if user.role != 'superadmin':
        return jsonify({'message': 'Access denied: Superadmins only'}), 403
    
    user_app.status = new_status
    db.session.commit()
    return jsonify({'message': f'User {user.username} status to {app_name} updated to {new_status}'}), 200

#Remove User from App
@app.route('/remove-app', methods=['DELETE'])
@jwt_required()
def remove_app():
    current_user = get_jwt_identity()
    user = User.query.filter_by(username=current_user).first()

    if not user:
        return jsonify({'message': 'User not found'}), 404

    data = request.get_json()
    username = data.get('username')
    app_name = data.get('app_name')

    user_to_remove = User.query.filter_by(username=username).first()
    app = App.query.filter_by(name=app_name).first()

    if not user_to_remove or not app:
        return jsonify({'message': 'User or app not found'}), 404
    
    user_app = UserApp.query.filter_by(user_id=user_to_remove.id, app_id=app.id).first()
    if not user_app:
        return jsonify({'message': 'User not assigned to this app'}), 404
    
    #Check if current user is superadmin
    if user.role != 'superadmin':
        return jsonify({'message': 'Access denied: Superadmins only'}), 403
    
    db.session.delete(user_app)
    db.session.commit()
    return jsonify({'message': f'User {user.username} removed from {app_name}'}), 200

#ADMIN PANEL
@app.route('/admin', methods=['GET'])
@jwt_required()
def admin_panel():
    current_user = get_jwt_identity()
    user = User.query.filter_by(username=current_user).first()
    
    if user.role != 'admin':
        return jsonify({'error': 'Access denied'}), 403
    
    return jsonify({'message': 'Welcome, Admin!'})

#UPDATE USER ROLE
@app.route('/update-role', methods=['PATCH'])
@jwt_required()
def update_role():
    current_user = get_jwt_identity()
    admin = User.query.filter_by(username=current_user).first()

    #Check if the user is an superadmin
    if not admin or admin.role != 'superadmin':
        return jsonify({'message': 'Access denied: Admins only'}), 403

    data = request.get_json()
    username = data.get('username')
    new_role = data.get('new_role')

    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'message': 'User not found'}), 404

    if not new_role:
        return jsonify({'message': 'Role cannot be empty'}), 400

    user.role = new_role
    db.session.commit()

    return jsonify({'message': f'User {username} role updated to {new_role}'}), 200


#SHOW ALL USERS
@app.route('/users', methods=['GET'])
@jwt_required()
def get_users():

    current_user = get_jwt_identity()
    admin = User.query.filter_by(username=current_user).first()

    if not admin or admin.role != 'admin':
        return jsonify({'message': 'Access denied: Admin)'}), 403

    users = User.query.all()
    return jsonify([
        {
            'id': user.id, 
            'username': user.username, 
            'password': user.password,
            'role': user.role  # Include role
        } 
        for user in users
    ])

#DELETE USER
@app.route('/delete-user', methods=['DELETE'])
@jwt_required()
def delete_user():
    current_user = get_jwt_identity()
    superadmin = User.query.filter_by(username=current_user).first()
    
    if not superadmin or superadmin.role != 'superadmin':
        return jsonify({'message': 'Access denied: Superadmins only'}), 403
    
    data = request.get_json()
    username = data.get('username')
    user = User.query.filter_by(username=username).first()
    
    if not user:
        return jsonify({'message': 'User not found'}), 404
    
    # Delete all UserApp entries associated with this user
    UserApp.query.filter_by(user_id=user.id).delete()
    db.session.delete(user)
    db.session.commit()
    
    return jsonify({'message': f'User {username} and associated data have been deleted'}), 200


if __name__ == '__main__':
    app.run(debug=True)



                        