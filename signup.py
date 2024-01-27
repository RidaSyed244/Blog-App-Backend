from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_pymongo import PyMongo
from werkzeug.security import generate_password_hash
from flask_jwt_extended import JWTManager
from flask_bcrypt import check_password_hash, generate_password_hash
import jwt
from datetime import datetime, timedelta
import secrets

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})
app.config["MONGO_URI"] = "mongodb://localhost:27017/BlogApp"
mongo = PyMongo(app)

gettoken= ''
@app.route('/signup', methods=['POST'])
def signup():
    try:
        data = request.get_json()

        userName = data.get('name')
        userEmail = data.get('email')
        userPassword = data.get('password')

        if userName and userEmail and userPassword and request.method == 'POST':
            existing_user = mongo.db.AllUsers.find_one({'email': userEmail})
            if existing_user:
                return jsonify({'error': 'Email already exists'}), 400

            hashed_password = generate_password_hash(userPassword)
            mongo.db.AllUsers.insert_one({'name': userName, 'email': userEmail, 'password': hashed_password})

            resp = {'message': 'User added successfully'}
            return jsonify(resp), 200
        else:
            return jsonify({'error': 'Invalid request'}), 400
    except Exception as e:
        print(e)
        return jsonify({'error': 'Internal Server Error'}), 500
    
@app.route('/login', methods=['POST'])
def login():
    global gettoken

    try:
        data = request.get_json()

        userName = data.get('name')
        userEmail = data.get('email')
        userPassword = data.get('password')

        if userEmail and userPassword and request.method == 'POST':
            existing_user = mongo.db.AllUsers.find_one({'email': userEmail})
            hashed_password = generate_password_hash(userPassword)

            if existing_user and    check_password_hash(existing_user['password'], hashed_password):
             
              
            #   get_token={
            #      "email": userEmail,
            #      "exp": datetime.utcnow() + timedelta(weeks=1)

            #   }
                print("User logged in successfully")
            #   secret_key = secrets.token_hex(32)
            #   app.config['SECRET_KEY'] = secret_key
            #   print(f"JWT Secret Key: {secret_key}")

            #   token = jwt.encode(get_token, app.config['SECRET_KEY'])
            #   gettoken = token
                resp = {'message': 'User logged in successfully'}
            return jsonify(resp), 200
        else:
            return jsonify({'error': 'Invalid request'}), 400
    except Exception as e:
        print(e)
        return jsonify({'error': 'Internal Server Error'}), 500
# @app.route('/getToken', methods=['GET'])
# def getToken():
#     global gettoken
#     return   gettoken

    

if __name__ == '__main__':
    app.run(debug=True)
