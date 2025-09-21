import datetime
import warnings
import asyncio
import bcrypt
import requests
from bs4 import BeautifulSoup
from database import (
    bus_routes_collection,
    bus_stops_collection,
    users_collection,
)
from requests.packages.urllib3.exceptions import InsecureRequestWarning  # type: ignore

# Suppress the InsecureRequestWarning that appears when using verify=False
warnings.simplefilter('ignore', InsecureRequestWarning)


async def check_user_async(email: str) -> bool:
    try:
        return await users_collection.find_one({"email": email}) is not None
    except Exception as e:
        print(f"Error while checking email: {e}")
        return False


async def get_user_by_email_async(email: str):
    try:
        user = await users_collection.find_one({"email": email}, {"_id": 0})
        return user
    except Exception as e:
        print(f"Error getting user by email: {e}")
        return None


async def create_user_async(
    email: str,
    name: str,
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
            "isEmailVerified": False,
            "created_at": datetime.datetime.now(datetime.timezone.utc),
            "password": hashed_password
        }
        await users_collection.insert_one(user)
        return True, "User created successfully."
    except Exception as e:
        print(f"Error while creating user: {e}")
        return False, "An error occurred while creating the user."


async def update_user_async(email: str, name: str, photo: str, password: str) -> tuple[bool, str]:
    try:
        update_fields = {}
        if name:
            update_fields["name"] = name
        if photo:
            update_fields["photo"] = photo
        if password:
            hashed_password = bcrypt.hashpw(
                password.encode('utf-8'), bcrypt.gensalt())
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


async def authenticate_user(email: str, password: str):
    try:
        user = await users_collection.find_one({"email": email})
        if user and bcrypt.checkpw(password.encode('utf-8'), user['password']):
            return user
        return None
    except Exception as e:
        print(f"Error authenticating user: {e}")
        return None


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
            filter=filter_query,
            projection={
                'stops': 0,
                '_id': 0
            }
        )
        return await cursor.to_list(None)
    except Exception as e:
        print(f"Error finding routes: {e}")
        return []


async def get_fare_details_async(origin_name: str, desti_name: str):
    url = "https://www.suratsitilink.org/GetFare.aspx"

    # Define a helper function to perform blocking I/O in a thread
    def fetch_fare_sync():
        try:
            # First, make a GET request to get the view state and validation tokens
            with requests.Session() as session:
                response_get = session.get(url, verify=False, timeout=10)
                response_get.raise_for_status()

                soup = BeautifulSoup(response_get.text, 'html.parser')

                # Extract all stop options and their values
                origin_stops = {option.text.strip(): option['value'] for option in soup.select(
                    '#ContentPlaceHolder1_ddlOriginStop option') if option.text.strip()}
                desti_stops = {option.text.strip(): option['value'] for option in soup.select(
                    '#ContentPlaceHolder1_ddlDestiStop option') if option.text.strip()}

                origin_value = origin_stops.get(origin_name)
                desti_value = desti_stops.get(desti_name)

                if not origin_value or not desti_value or origin_value == desti_value:
                    return {"error": "Invalid origin or destination stop name."}

                # Extract hidden form fields for validation
                viewstate = soup.select_one('#__VIEWSTATE')['value']
                eventvalidation = soup.select_one(
                    '#__EVENTVALIDATION')['value']

                # Prepare the form data for the POST request
                formdata = {
                    'ctl00$ContentPlaceHolder1$ddlOriginStop': origin_value,
                    'ctl00$ContentPlaceHolder1$ddlDestiStop': desti_value,
                    '__EVENTTARGET': 'ctl00$ContentPlaceHolder1$ddlDestiStop',
                    '__VIEWSTATE': viewstate,
                    '__EVENTVALIDATION': eventvalidation,
                }

                # Make the POST request to get the fare details
                response_post = session.post(
                    url, data=formdata, verify=False, timeout=10)
                response_post.raise_for_status()

                post_soup = BeautifulSoup(response_post.text, 'html.parser')
                fare_table = post_soup.select_one(
                    '#ContentPlaceHolder1_dvfaredetail .table-bordered')

                if not fare_table:
                    return {"error": "Could not find the fare table after form submission."}

                # Parse the fare table
                extracted_fare = {}
                headers = [th.text.strip()
                           for th in fare_table.select('thead th')]

                for row in fare_table.select('tbody tr'):
                    row_header_element = row.select_one('th')
                    if not row_header_element:
                        continue
                    row_header = row_header_element.text.strip()
                    cells = [td.text.strip() for td in row.select('td')]

                    if len(cells) == len(headers) - 1:
                        row_data = {headers[i+1]: cells[i]
                                    for i in range(len(cells))}
                        extracted_fare[row_header] = row_data

                if extracted_fare:
                    return extracted_fare
                else:
                    return {"error": "Fare details not found."}

        except requests.exceptions.RequestException as e:
            print(f"Request failed: {e}")
            return {"error": f"Failed to fetch fare data: {e}"}
        except Exception as e:
            print(f"An unexpected error occurred: {e}")
            return {"error": f"An unexpected error occurred: {e}"}

    # Run the synchronous function in a thread to avoid blocking the event loop
    return await asyncio.to_thread(fetch_fare_sync)
