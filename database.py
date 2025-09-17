import motor.motor_asyncio as motor
from config import config

class Database:
    _instance = None

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = motor.AsyncIOMotorClient(config.MONGO_URI)
        return cls._instance

def get_db():
    client = Database.get_instance()
    return client["Surat_Sitilink"]

db = get_db()
bus_routes_collection = db["bus_routes"]
bus_stops_collection = db["bus_stops"]
