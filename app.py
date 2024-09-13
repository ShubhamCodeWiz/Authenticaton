from flask import Flask
from flask_restful import Api
from flask_jwt_extended import JWTManager
from models import db
from auth_blueprint import Register,Login,ProtectedResource,auth,Userlist
from config import Config
import logging
from flask_migrate import Migrate
from flasgger import Swagger


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    db.init_app(app)
    migrate = Migrate(app,db)

    api = Api(auth)
    jwt = JWTManager(app)
    swagger = Swagger(app)

    app.register_blueprint(auth,url_prefix="/auth")

    api.add_resource(Register,"/register")
    api.add_resource(Login,"/login")
    api.add_resource(ProtectedResource,"/protected")
    api.add_resource(Userlist,"/users")

    logging.basicConfig(level=logging.INFO)

    return app

if __name__ == "__main__":
    app = create_app()
    with app.app_context():
        db.create_all()
    app.run(debug=True)



        