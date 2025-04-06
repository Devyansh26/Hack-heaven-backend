from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
# from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
# from functools import wraps





app = Flask(__name__)
# Enable CORS for all routes and all origins
CORS(app, supports_credentials=True, resources={r"/*": {"origins": "*"}})

# Config SQLite DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'your-secret-key'

db = SQLAlchemy(app)
jwt = JWTManager(app)



# User model
class User(db.Model):
    __tablename__ = 'users'  # ensure this matches your actual table name
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    bio = db.Column(db.Text, nullable=True)
    followers = db.Column(db.Integer, default=100)
    coins = db.Column(db.Integer, default=200)
    avatar = db.Column(db.String(200), nullable=True)  # path to avatar image

# Create tables
with app.app_context():
    db.create_all()

# Simple root endpoint for connection testing
@app.route('/', methods=['GET'])
def home():
    return jsonify({"message": "Server is running"}), 200
    
@app.route('/signup', methods=['POST'])
def signup():
    try:
        data = request.get_json()
        print("Received data:", data)  # Debug: Log incoming data
        
        username = data.get("username")
        email = data.get("email")
        password = data.get("password")

        if not all([username, email, password]):
            return jsonify({"message": "Missing data"}), 400

        if User.query.filter_by(email=email).first():
            return jsonify({"message": "User already exists"}), 400

        hashed_password = generate_password_hash(password)
        new_user = User(username=username, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        token = create_access_token(identity=email)
        return jsonify(access_token=token, user=username, email=email), 201
    
    except Exception as e:
        print(f"Error during signup: {str(e)}")  # Debug: Log errors
        return jsonify({"message": f"Server error: {str(e)}"}), 500

@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        email = data.get("email")
        password = data.get("password")

        user = User.query.filter_by(email=email).first()

        if not user or not check_password_hash(user.password, password):
            return jsonify({"message": "Invalid credentials"}), 401

        token = create_access_token(identity=email)
        # Store user email in local storage for later use
        return jsonify(access_token=token, user=user.username, email=user.email), 200
    
    except Exception as e:
        print(f"Error during login: {str(e)}")
        return jsonify({"message": f"Server error: {str(e)}"}), 500


@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user_email = get_jwt_identity()
    user = User.query.filter_by(email=current_user_email).first()
    if not user:
        return jsonify({"message": "User not found"}), 404
    return jsonify(logged_in_as=user.username)


@app.route("/profile", methods=["GET"])
@jwt_required()
def get_profile():
    try:
        # Get the user's email from the JWT token
        current_user_email = get_jwt_identity()
        print(f"Getting profile for: {current_user_email}")
        
        user = User.query.filter_by(email=current_user_email).first()

        if not user:
            print("User not found")
            return jsonify({"message": "User not found"}), 404

        print("User found, returning profile")
        return jsonify({
            "username": user.username,
            "name": user.username,  # For compatibility with the frontend
            "email": user.email,
            "bio": user.bio or "",  # Handle None values
            "followers": user.followers,
            "coins": user.coins,
            "avatar": user.avatar or "/default/avatar.jpg"
        })
    except Exception as e:
        print(f"Error in get_profile: {str(e)}")
        return jsonify({"message": f"Server error: {str(e)}"}), 500

@app.route("/update-profile", methods=["POST"])
@jwt_required()
def update_profile():
    try:
        # Get the user's email from the JWT token
        current_user_email = get_jwt_identity()
        user = User.query.filter_by(email=current_user_email).first()
        
        if not user:
            return jsonify({"message": "User not found"}), 404
        data = request.get_json()
        
        # Update user fields with data from the request
        if data.get("name"):
            user.username = data.get("name")  # Update username
        
        if data.get("email"):
            user.email = data.get("email")  # Update email
        
        if "bio" in data:
            user.bio = data.get("bio")  # Update bio
        
        db.session.commit()
        return jsonify({"message": "Profile updated successfully"}), 200
    except Exception as e:
        db.session.rollback()
        print(f"Error in update_profile: {str(e)}")
        return jsonify({"message": f"Failed to update profile: {str(e)}"}), 500

@app.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    try:
        current_user_email = get_jwt_identity()
        # No server-side token invalidation here; client will remove the token
        return jsonify({"message": "Logged out successfully"}), 200
    except Exception as e:
        print(f"Error during logout: {str(e)}")
        return jsonify({"message": f"Server error: {str(e)}"}), 500


if __name__ == '__main__':
    app.run(debug=True)