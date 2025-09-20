from bson.objectid import ObjectId
import bcrypt
import datetime
import geopy.geocoders as geocoders
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


async def create_user_async(
        email: str,
        name: str,
        provider: str,
        photo: str = None,
        password: str = None
    ) -> tuple[bool, str]:
    try:
        hashed_password = bcrypt.hashpw(
            password.encode('utf-8'), bcrypt.gensalt())
        user = {
            "email": email,
            "name": name,
            "photo": photo,
            "provider": provider,
            "created_at": datetime.datetime.now(datetime.timezone.utc),
            "password": hashed_password
        }
        await users_collection.insert_one(user)
        return True, "User created successfully."
    except Exception as e:
        print(f"Error while creating user: {e}")
        return False, "An error occurred while creating the user."

async def update_user_async(email : str, name : str, photo : str, password : str) -> tuple[bool, str]:
    try:
        update_fields = {
            "name": name,
            "photo": photo
        }
        if password:
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            update_fields["password"] = hashed_password

        result = await users_collection.update_one(
            {"email": email},
            {"$set": update_fields}
        )
        if result.modified_count == 1:
            return True, "User updated successfully."
        else:
            return False, "No changes made to the user."
    except Exception as e:
        print(f"Error while updating user: {e}")
        return False, "An error occurred while updating the user."
    
async def get_route_by_id_async(route_id: str):
    try:
        route = await bus_routes_collection.find_one({"service_no": route_id}, {"stops": 1, '_id': 0})
        return route
    except Exception as e:
        print(f"Error getting route by ID: {e}")
        return None

async def get_all_routes_async():
    try:
        cursor = bus_routes_collection.find({}, {"stops": 0, '_id': 0})
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
        cursor = bus_routes_collection.find(
            filter = filter_query, 
            projection = {
                'stops': 0, 
                '_id': 0
                }
            )
        return await cursor.to_list(None)
    except Exception as e:
        print(f"Error finding routes: {e}")
        return []
