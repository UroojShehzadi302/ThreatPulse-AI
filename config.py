import os
from dotenv import load_dotenv

# .env file se secrets load karein
load_dotenv()

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'default_fallback_key')
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', 'sqlite:///threatpulse.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False