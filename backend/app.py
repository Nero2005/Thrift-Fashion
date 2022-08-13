from enum import unique
import os
SECRET_KEY = os.getenv('SECRET_KEY', 'my_precious')
import bcrypt
from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from marshmallow_sqlalchemy import SQLAlchemySchema
from marshmallow import fields
import jwt
import datetime

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI']='mysql+pymysql://root:nero2005@localhost:3306/newdb'
db = SQLAlchemy(app)

def encode_auth_token(user_id):
    """
    Generates the Auth Token
    :return: string
    """
    try:
        payload = {
            'exp': datetime.datetime.utcnow() + datetime.timedelta(days=1, seconds=5),
            'iat': datetime.datetime.utcnow(),
            'sub': user_id
        }
        token = jwt.encode(
            payload,
            SECRET_KEY,
            algorithm='HS256'
        )
        return token
    except Exception as e:
        return e

def decode_auth_token(auth_token):
    """
    Decodes the auth token
    :param auth_token:
    :return: integer|string
    """
    try:
        payload = jwt.decode(auth_token, SECRET_KEY, algorithms=['HS256'])
        return payload['sub']
    except jwt.ExpiredSignatureError as e:
        print(e)
        return 'Signature expired. Please log in again.'
    except jwt.InvalidTokenError as e:
        print(e)
        return 'Invalid token. Please log in again.'

class Product(db.Model):
    __tablename__ = "products"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    title = db.Column(db.String(20))
    productDescription = db.Column(db.String(100))
    productBrand = db.Column(db.String(20))
    price = db.Column(db.Integer)
    launchDate = db.Column(db.DateTime)

    def create(self):
      db.session.add(self)
      db.session.commit()
      return self
    def __init__(self,title,productDescription,productBrand,price):
        self.title = title
        self.productDescription = productDescription
        self.productBrand = productBrand
        self.price = price
        self.launchDate = datetime.datetime.now()
    def __repr__(self):
        return '' % self.id


class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)

    def create(self):
      db.session.add(self)
      db.session.commit()
      return self
    def __init__(self,email,password):
        self.email = email
        self.password = password
    def __repr__(self):
        return '' % self.id

class ProductSchema(SQLAlchemySchema):
    class Meta(SQLAlchemySchema.Meta):
        model = Product
        sqla_session = db.session
    id = fields.Number(dump_only=True)
    title = fields.String(required=True)
    productDescription = fields.String(required=True)
    productBrand = fields.String(required=True)
    price = fields.Number(required=True)
    launchDate = fields.DateTime(dump_only=True)

@app.route("/auth/register", methods= ['POST'])
def register():
    data = request.get_json()
    user = User.query.filter_by(email=data.get('email')).first()
    if not user:
        try:
            user = User(
                email=data.get('email'),
                password=bcrypt.hashpw(data.get('password').encode('utf-8'), bcrypt.gensalt(10))
            )

            # insert the user
            db.session.add(user)
            db.session.commit()
            print(user.id);
            # generate the auth token
            auth_token = encode_auth_token(user_id=user.id)
            print(auth_token)
            # 'auth_token': auth_token
            responseObject = {
                'status': 'success',
                'message': 'Successfully registered.',
                'auth_token': auth_token
            }
            return make_response(jsonify(responseObject)), 201
        except Exception as e:
            responseObject = {
                'status': 'fail',
                'message': 'Some error occurred. Please try again.',
            }
            print(e)
            return make_response(jsonify(responseObject)), 401
    else:
        responseObject = {
            'status': 'fail',
            'message': 'User already exists. Please Log in.',
        }
        return make_response(jsonify(responseObject)), 202

@app.route("/auth/login", methods= ['POST'])
def login():
    # get the post data
    post_data = request.get_json()
    try:
        # fetch the user data
        email = post_data.get('email')
        password = post_data.get('password')
        user = User.query.filter_by(
            email=email
        ).first()
        if not user:
            responseObject = {
                'status': 'fail',
                'message': 'User doesn\'t exist.',
            }
            return make_response(jsonify(responseObject)), 404
        correct = bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8'))
        if not correct:
            responseObject = {
                'status': 'fail',
                'message': 'Password incorrect',
            }
            return make_response(jsonify(responseObject)), 401
        
        auth_token = encode_auth_token(user.id)
        if auth_token:
            print(len(auth_token))
            print(auth_token)
            responseObject = {
                'status': 'success',
                'message': 'Successfully logged in.',
                'auth_token': auth_token
            }
            return make_response(jsonify(responseObject)), 200
    except Exception as e:
        print(e)
        responseObject = {
            'status': 'fail',
            'message': 'Try again',
        }
        return make_response(jsonify(responseObject)), 500

def authenticate(token):
    if token:
        print(len(token))
        print(token)
        resp = decode_auth_token(token)
        return resp

@app.route('/users/me', methods = ['GET'])
def me():
    auth_header = request.headers.get('Authorization')
    try:
        if not auth_header:
            responseObject = {
                'status': 'fail',
                'message': 'Provide a valid auth token.'
            }
            return make_response(jsonify(responseObject)), 401
        resp = authenticate(auth_header)
        if not isinstance(resp, str):
            user = User.query.filter_by(id=resp).first()
            responseObject = {
                'status': 'success',
                'data': {
                    'user_id': user.id,
                    'email': user.email,
                }
            }
            return make_response(jsonify(responseObject)), 200
        responseObject = {
            'status': 'fail',
            'message': resp
        }
        return make_response(jsonify(responseObject)), 401
    except Exception as e:
        responseObject = {
            'status': 'fail',
            'message': 'Error'
        }
        print(e)
        return make_response(jsonify(responseObject)), 500
    

@app.route('/products', methods = ['POST'])
def create_product():
    auth_header = request.headers.get('Authorization')
    try:
        if not auth_header:
            responseObject = {
                'status': 'fail',
                'message': 'Provide a valid auth token.'
            }
            return make_response(jsonify(responseObject)), 401
        resp = authenticate(auth_header)
        if not isinstance(resp, str):
            data = request.get_json()
            product = Product(
                title=data.get('title'),
                productBrand=data.get('productBrand'),
                productDescription=data.get('productDescription'),
                price=data.get('price')
            )
            db.session.add(product)
            db.session.commit()
            return make_response(jsonify({"product": product.id, 'status': 'success'}),200)
            # data = request.get_json()
            # product_schema = ProductSchema()
            # product = product_schema.load(data)
            # result = product_schema.dump(product.create())
            # return make_response(jsonify({"product": result}),200)
        responseObject = {
            'status': 'fail',
            'message': resp
        }
        return make_response(jsonify(responseObject)), 401
    except Exception as e:
        responseObject = {
            'status': 'fail',
            'message': 'Error'
        }
        print(e)
        return make_response(jsonify(responseObject)), 500

@app.route('/products', methods = ['GET'])
def index():
    try:
        get_products = Product.query.all()
        # print(get_products)
        product_schema = ProductSchema(many=True)
        products = product_schema.dump(get_products)
        return make_response(jsonify({"products": products})), 200
    except Exception as e:
        print(e)
        return make_response(jsonify({"message": "Error"})), 500

db.create_all()