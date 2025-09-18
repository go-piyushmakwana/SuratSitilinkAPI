from bson.objectid import ObjectId
import bcrypt
import datetime
from database import (
    users_collection,
    bus_routes_collection,
    bus_stops_collection,
)


async def check_user_async(email: str) -> bool:
    try:
        return await users_collection.find_one({"email": email}) is not None
    except Exception as e:
        print(f"Error while checking email: {e}")
        return False


async def create_user_async(name: str, email: str, password: str, mobile: str) -> tuple[bool, str]:
    try:
        hashed_password = bcrypt.hashpw(
            password.encode('utf-8'), bcrypt.gensalt())
        user = {
            "name": name,
            "email": email,
            "password": hashed_password,
            "mobile": mobile,
            "created_at": datetime.datetime.now(datetime.timezone.utc)
        }
        await users_collection.insert_one(user)
        return True, "User created successfully."
    except Exception as e:
        print(f"Error while creating user: {e}")
        return False, "An error occurred while creating the user."


async def validate_user_async(email: str, password: str) -> bool:
    try:
        user = await users_collection.find_one({"email": email})
        if user and bcrypt.checkpw(password.encode('utf-8'), user['password']):
            return True
        return False
    except Exception as e:
        print(f"Error while validating user: {e}")
        return False

async def get_route_by_id_async(route_id: str):
    try:
        route = await bus_routes_collection.find_one({"service_no": route_id.upper()}, {"_id": 0})
        return route
    except Exception as e:
        print(f"Error getting route by ID: {e}")
        return None

async def get_all_routes_async():
    try:
        cursor = bus_routes_collection.find({}, {"_id": 0})
        return await cursor.to_list(None)
    except Exception as e:
        print(f"Error getting routes: {e}")
        return []


async def get_all_stops_async():
    try:
        cursor = bus_stops_collection.find({}, {"_id": 0})
        return await cursor.to_list(None)
    except Exception as e:
        print(f"Error getting stops: {e}")
        return []


async def find_routes_between_stops_async(origin: str, destination: str):
    try:
        filter_query = {
            "$and": [
                {"stops": {"$elemMatch": {"name": {"$regex": origin, "$options": "i"}}}},
                {"stops": {"$elemMatch": {"name": {"$regex": destination, "$options": "i"}}}}
            ]
        }
        cursor = bus_routes_collection.find(filter_query, {"_id": 0})
        return await cursor.to_list(None)
    except Exception as e:
        print(f"Error finding routes: {e}")
        return []
