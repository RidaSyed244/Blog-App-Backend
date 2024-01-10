from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
## Firstly install PyMongo using pip install PyMongo and pip install Flask-PyMongo
from flask_pymongo import PyMongo
from bson import ObjectId  
from werkzeug.security import generate_password_hash

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})
app.config["MONGO_URI"] = "mongodb://localhost:27017/BlogApp"
mongo = PyMongo(app)

@app.route('/signup', methods=['POST'])
def signup():
    try:
        userName = request.form.get('name')
        userEmail = request.form.get('email')
        userPassword = request.form.get('password')

        if userName and userEmail and userPassword and request.method == 'POST':
            existing_user = mongo.db.AllUsers.find_one({'email': userEmail})
            if existing_user:
                return jsonify({'error': 'Email already exists'}), 400

            hashed_password = generate_password_hash(userPassword)
            mongo.db.AllUsers.insert({'name': userName, 'email': userEmail, 'password': hashed_password})

            resp = {'message': 'User added successfully'}
            return jsonify(resp), 200
        else:
            return jsonify({'error': 'Invalid request'}), 400
    except Exception as e:
        print(e)
        return jsonify({'error': 'Internal Server Error'}), 500

if __name__ == '__main__':
    app.run(debug=True)
