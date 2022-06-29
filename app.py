import datetime
from functools import wraps
import os

import boto3
from flask import Flask, jsonify, make_response, request
import jwt
from werkzeug.security import generate_password_hash, check_password_hash
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ['SECRET_KEY']  # "mysecret123"


dynamodb_client = boto3.client('dynamodb')

if os.environ.get('IS_OFFLINE'):
    dynamodb_client = boto3.client(
        'dynamodb', region_name='localhost', endpoint_url='http://localhost:8000'
    )
USERS_TABLE = os.environ['USERS_TABLE']
# decorator for verifying the JWT


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):

        token = None
        # jwt is passed in the request header
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        # return 401 if token is not passed
        if not token:
            return jsonify({'message': 'Token is missing !!'}), 401

        try:
            # decoding the payload to fetch the stored details
            data = jwt.decode(
                token, app.config['SECRET_KEY'], algorithms=['HS256'])
            result = dynamodb_client.get_item(
                TableName=USERS_TABLE, Key={'userId': {'S': data['userId']}}
            )

        except Exception as e:

            return jsonify({
                'message': 'Token is invalid !!'
            }), 401
        # returns the current logged in users contex to the routes
        return f(data['userId'])

    return decorated


USERS_TABLE = os.environ['USERS_TABLE']

# Route for deleting user based on userid


@app.route('/delete_user/<string:user_id>')
@token_required
def delete_user(user_id):

    # table = dynamodb_client.Table(USERS_TABLE)
    dynamodb_client.delete_item(
        TableName=USERS_TABLE, Key={'userId':  {"S": (user_id)}}
    )

    return jsonify(
        {'message': 'User successfully deleted'}
    )

# Route for getting user based on userid


@app.route('/users/<string:user_id>')
@token_required
def get_user(user_id):
    result = dynamodb_client.get_item(
        TableName=USERS_TABLE, Key={'userId': {'S': user_id}}
    )
    item = result.get('Item')
    if not item:
        return jsonify({'error': 'Could not find user with provided "userId"'}), 404

    return jsonify(
        {'userId': item.get('userId').get(
            'S'), 'email': item.get('email').get('S')}
    )

# Route for creating user (Not used)


@app.route('/users', methods=['POST'])
@token_required
def create_user():
    user_id = request.json.get('userId')
    name = request.json.get('name')
    if not user_id or not name:
        return jsonify({'error': 'Please provide both "userId" and "name"'}), 400

    dynamodb_client.put_item(
        TableName=USERS_TABLE, Item={
            'userId': {'S': user_id}, 'name': {'S': name}}
    )

    return jsonify({'userId': user_id, 'name': name})

# Route for logging user in


@app.route('/login', methods=['POST'])
def login():

    if not request.json.get('password') or not request.json.get('userId'):
        # returns 401 if any userId or / and password is missing
        return make_response(
            'Could not verify',
            401,
            {'WWW-Authenticate': 'Basic realm ="Login required !!"'}
        )
    result = dynamodb_client.get_item(
        TableName=USERS_TABLE, Key={
            'userId': {'S': request.json.get('userId')}}
    )
    item = result.get('Item')

    if not item:
        # returns 401 if user does not exist
        return make_response(
            'Could not verify',
            401,
            {'WWW-Authenticate': 'Basic realm ="User does not exist !!"'}
        )

    if check_password_hash(item.get('password').get('S'), request.json.get('password')):
        # generates the JWT Token
        token = jwt.encode({
            'userId': item.get('userId').get('S'),
            'exp': datetime.datetime.now() + datetime.timedelta(minutes=30)
        }, app.config['SECRET_KEY'], algorithm='HS256')

        return make_response(jsonify({'token': token}), 201)
    # returns 403 if password is wrong
    return make_response(
        'Could not verify',
        403,
        {'WWW-Authenticate': 'Basic realm ="Wrong Password !!"'}
    )

# Route for signing up


@app.route('/signup', methods=['POST'])
def signup():

    # gets name, email and password
    userId, email = request.json.get('userId'), request.json.get('email')
    password = request.json.get('password')
    result = dynamodb_client.get_item(
        TableName=USERS_TABLE, Key={'userId': {'S': userId}}
    )
    item = result.get('Item')

    if not item:
        # database ORM object
        dynamodb_client.put_item(
            TableName=USERS_TABLE, Item={'userId': {'S': userId}, 'email': {
                'S': email}, 'password': {'S': generate_password_hash(password)}}
        )

        return make_response('Successfully registered.', 201)
    else:
        # returns 202 if user already exists
        return make_response('User already exists. Please Log in.', 202)


@app.errorhandler(404)
def resource_not_found(e):
    return make_response(jsonify(error='Not found!'), 404)
