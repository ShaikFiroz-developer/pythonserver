import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    # Use env vars; avoid hardcoding secrets in code. Configure these in your hosting provider.
    MONGO_URI = os.environ.get('MONGO_URI', '')
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', '')
    SENDER_EMAIL = os.environ.get('SENDER_EMAIL', '')
    SENDER_PASSWORD = os.environ.get('SENDER_PASSWORD', '')
    DEBUG = False

class DevelopmentConfig(Config):
    DEBUG = True

class ProductionConfig(Config):
    pass  # Add prod-specific overrides, e.g., logging levels