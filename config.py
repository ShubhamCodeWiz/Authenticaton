import os
from datetime import timedelta

class Config:
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///database.db')
    SECRET_KEY = os.environ.get('SECRET_KEY', "'b'\x9aY\xec\xd0\x9e\xd6 A\x96\xb2\xa1|eA\x95b'")
    SQLALCHEMY_TRACK_MODIFICATIONS = False


    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', "aYxecxd0x9exd6 Ax96xb")
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=30)