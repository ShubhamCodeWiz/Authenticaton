from flask import request, Blueprint
from flask_restful import Api, Resource
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import check_password_hash, generate_password_hash
from flasgger import Swagger, swag_from
from models import Registration, db
import logging
import pytz

logger = logging.getLogger(__name__)
auth = Blueprint("auth_blueprint", __name__)
api = Api(auth)

class Register(Resource):
    @swag_from({
        'tags': ['Authentication'],
        'description': 'Register a new user',
        'parameters': [
            {
                'name': 'body',
                'in': 'body',
                'schema': {
                    'type': 'object',
                    'properties': {
                        'username': {'type': 'string'},
                        'password': {'type': 'string'},
                        'confirm_password': {'type': 'string'}
                    },
                    'required': ['username', 'password', 'confirm_password']
                }
            }
        ],
        'responses': {
            '201': {
                'description': 'User registered successfully',
                'schema': {
                    'type': 'object',
                    'properties': {
                        'message': {'type': 'string'}
                    }
                }
            },
            '400': {
                'description': 'Bad request',
                'schema': {
                    'type': 'object',
                    'properties': {
                        'error': {'type': 'string'}
                    }
                }
            },
            '500': {
                'description': 'Internal server error',
                'schema': {
                    'type': 'object',
                    'properties': {
                        'error': {'type': 'string'}
                    }
                }
            }
        }
    })
    def post(self):
        if not request.is_json:
            return {"error": "request must be in json format"}, 400
        args = request.get_json()
        username = args.get("username")
        password = args.get("password")
        confirm_password = args.get("confirm_password")
        if not username or not password or not confirm_password:
            return {"error": "All fields are required"}, 400
        if password != confirm_password:
            return {"error": "password does not match!"}, 400
        user = Registration.query.filter_by(username=username).first()
        if user:
            return {"error": "username already exist!"}, 400
        hash_password = generate_password_hash(password)
        new_user = Registration(username=username, password=hash_password)
        try:
            db.session.add(new_user)
            db.session.commit()
            logger.info(f"New user registered, {username}")
        except Exception as e:
            logger.error(f"Unexpected error during registration! {str(e)}")
            db.session.rollback()
            return {"error": "unexpected error occurred! please try again later."}, 500
        return {"message": "New user registered successfully"}, 201

class Login(Resource):
    @swag_from({
        'tags': ['Authentication'],
        'description': 'Login user and return access token',
        'parameters': [
            {
                'name': 'body',
                'in': 'body',
                'schema': {
                    'type': 'object',
                    'properties': {
                        'username': {'type': 'string'},
                        'password': {'type': 'string'}
                    },
                    'required': ['username', 'password']
                }
            }
        ],
        'responses': {
            '200': {
                'description': 'Login successful',
                'schema': {
                    'type': 'object',
                    'properties': {
                        'message': {'type': 'string'},
                        'access_token': {'type': 'string'}
                    }
                }
            },
            '400': {
                'description': 'Bad request',
                'schema': {
                    'type': 'object',
                    'properties': {
                        'error': {'type': 'string'}
                    }
                }
            },
            '401': {
                'description': 'Unauthorized',
                'schema': {
                    'type': 'object',
                    'properties': {
                        'error': {'type': 'string'}
                    }
                }
            },
            '500': {
                'description': 'Internal server error',
                'schema': {
                    'type': 'object',
                    'properties': {
                        'error': {'type': 'string'}
                    }
                }
            }
        }
    })
    def get(self):
        try:
            if not request.is_json:
                return {"error": "request must be in json format"}, 400
            args = request.get_json()
            username = args.get("username")
            password = args.get("password")
            if not username or not password:
                return {"error": "All fields are required"}, 400
            user_exist = Registration.query.filter_by(username=username).first()
            if not user_exist:
                return {"error": "invalid username!"}, 401
            if not check_password_hash(user_exist.password, password):
                return {"error": "invalid password!"}, 401
            logger.info(f"user logged in, {username}")
            access_token = create_access_token(identity=username)
            return {"message": f"successfully logged in as, {username}", "access_token": access_token}, 200
        except Exception as e:
            logger.error(f"Unexpected error during login! {str(e)}")
            return {"error": "unexpected error occurred! please try again later."}, 500

class Userlist(Resource):
    @swag_from({
        'tags': ['Users'],
        'description': 'Get list of all users',
        'responses': {
            '200': {
                'description': 'List of users',
                'schema': {
                    'type': 'array',
                    'items': {
                        'type': 'object',
                        'properties': {
                            'id': {'type': 'integer'},
                            'name': {'type': 'string'},
                            'registered_at': {'type': 'string', 'format': 'date-time'}
                        }
                    }
                }
            }
        }
    })
    def get(self):
        all_user = Registration.query.all()
        all_user_list = []
        india_tz = pytz.timezone('Asia/Kolkata')
        for user in all_user:
            ist_time = user.created_at.astimezone(india_tz)
            user_dict = {
                "id": user.id,
                "name": user.username,
                "registered_at": ist_time.strftime('%Y-%m-%d %H:%M:%S')
            }
            all_user_list.append(user_dict)
        return all_user_list

class ProtectedResource(Resource):
    @jwt_required()
    @swag_from({
        'tags': ['Protected'],
        'description': 'Access protected resource',
        'parameters': [
            {
                'name': 'Authorization',
                'in': 'header',
                'type': 'string',
                'required': True,
                'description': 'JWT token'
            }
        ],
        'responses': {
            '200': {
                'description': 'Protected resource accessed',
                'schema': {
                    'type': 'object',
                    'properties': {
                        'logged_in_as': {'type': 'string'}
                    }
                }
            },
            '401': {
                'description': 'Unauthorized',
                'schema': {
                    'type': 'object',
                    'properties': {
                        'msg': {'type': 'string'}
                    }
                }
            }
        }
    })
    def get(self):
        current_user = get_jwt_identity()
        return {"logged_in_as": current_user}, 200



