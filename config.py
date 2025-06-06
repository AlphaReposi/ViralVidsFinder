import os
from dotenv import load_dotenv

load_dotenv()

class config:
    SECRET_KEY = os.getenv("SECRET_KEY", "23f9330e0460e9e032edd8419a43d078445eddffe9d99660d3fa03d8f75d2afb")
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL", "sqlite:///users.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY", "sk_test_51RIBXnCpHVRe7A1XjMceKi8P8BxoEyVgvrdKjt5KmPEe9jc6oCbDxrEXm2ylAFOMTFRQ3D6ngCCzaJhhTEmeRqXg00BAab1WsA")
    STRIPE_BASIC_PLAN_ID = "price_1RIuygCpHVRe7A1Xrai8TSAV"
    STRIPE_PRO_PLAN_ID = "price_1RIuzaCpHVRe7A1XjH8KcFTS"
    STRIPE_ELITE_PLAN_ID = "price_1RIv0HCpHVRe7A1XcCL8m0Vz"
    STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "whsec_your_webhook_secret")
    MAX_YOUTUBE_HISTORY = int(os.getenv("MAX_YOUTUBE_HISTORY", 15))
    MAX_TIKTOK_HISTORY = int(os.getenv("MAX_TIKTOK_HISTORY", 15))
    MAX_REEL_HISTORY = int(os.getenv("MAX_REEL_HISTORY", 15))
