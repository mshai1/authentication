from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class App(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="user")  # Admin, Manager, Member

class UserApp(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    app_id = db.Column(db.Integer, db.ForeignKey('app.id'), nullable=False)
    access_level = db.Column(db.String(20), nullable=False)  # Admin, Manager, Member

    user = db.relationship('User', backref=db.backref('user_apps', cascade="all, delete-orphan"))
    app = db.relationship('App', backref=db.backref('user_apps', cascade="all, delete-orphan"))


    def __repr__(self):
        return f'<User {self.username}>'