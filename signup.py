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
objectId= ''
AlltextBlogs=[]
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

            mongo.db.AllUsers.insert_one({'name': userName, 'email': userEmail, 'password': userPassword})

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
    global objectId
    try:
        data = request.get_json()

        userName = data.get('name')
        userEmail = data.get('email')
        userPassword = data.get('password')

        if userEmail and userPassword and request.method == 'POST':
            existing_user = mongo.db.AllUsers.find_one({'email': userEmail, 'name': userName, 'password': userPassword})

            if existing_user:
                get_token = {
                    "email": userEmail,
                    "exp": datetime.utcnow() + timedelta(weeks=1)
                }
                secret_key = secrets.token_hex(32)
                app.config['SECRET_KEY'] = secret_key
                gettoken = jwt.encode(get_token, app.config['SECRET_KEY'])
                objectId = existing_user['_id']
                resp = {'message': 'User logged in successfully'}
                print("User logged in successfully")
                return jsonify(resp), 200
            else:
                resp = {'error': 'Issue occured while logging in'}
                return jsonify(resp), 401

        else:
            resp = {'error': 'Invalid email or password'}
            return jsonify(resp), 200
    except Exception as e:
        print(e)
        return jsonify({'error': 'Internal Server Error'}), 500
@app.route('/getUserId', methods=['GET'])
def getUserId():
    global objectId
    print(objectId)
    return jsonify({'_id': str(objectId)})  # Convert ObjectId to string
@app.route('/getToken', methods=['GET'])
def getToken():
    global gettoken
    return   jsonify({'token': gettoken})


@app.route("/allTextBlogs", methods= ["GET"])
def allTextBlogs():
    try:
        allBlogs = mongo.db.TextBlog.find({}, {"_id": 0, "textBlog": 1, "userId": 1})
        textBlogs_list = [{"textBlog": blog["textBlog"], "userId": blog["userId"]} for blog in allBlogs]
        return jsonify(textBlogs_list), 200
    except Exception as e:
        print(e)
        return jsonify({'error': 'Internal Server Error'}), 500
@app.route("/textBlog", methods= ["POST"])
def textBlog():
    try:
        data = request.get_json()
        textBlog = data.get('textBlog')
        userToken = data.get('userId')

        if textBlog and userToken and request.method == 'POST':
            mongo.db.TextBlog.insert_one({'textBlog': textBlog, 'userId': userToken})
            resp = {'message': 'Text added successfully'}
            return jsonify(resp), 200
        else:
            return jsonify({'error': 'Invalid request'}), 400
    except Exception as e:
        print(e)
        return jsonify({'error': 'Internal Server Error'}), 500
if __name__ == '__main__':
    app.run(debug=True, host='192.168.1.107', port=5000)
