from bson.objectid import ObjectId
import bcrypt
import datetime
import requests
import warnings
from bs4 import BeautifulSoup
from database import (
    users_collection,
    bus_routes_collection,
    bus_stops_collection,
)

warnings.simplefilter(
    'ignore', requests.packages.urllib3.exceptions.InsecureRequestWarning)


async def check_user_async(email: str) -> bool:
    try:
        return await users_collection.find_one({"email": email}) is not None
    except Exception as e:
        print(f"Error while checking email: {e}")
        return False


async def get_fare_details_async(origin_name: str, desti_name: str):
    """
    Fetches fare details for a specific bus route from the Surat Sitilink website.
    """
    url = "https://www.suratsitilink.org/GetFare.aspx"

    try:
        # Step 1: Get the dropdown values for the stops
        get_response = requests.get(url, verify=False)
        get_soup = BeautifulSoup(get_response.text, 'html.parser')

        origin_stops = {option.text.strip(): option.get('value') for option in get_soup.find(
            'select', {'id': 'ContentPlaceHolder1_ddlOriginStop'}).find_all('option')}
        desti_stops = {option.text.strip(): option.get('value') for option in get_soup.find(
            'select', {'id': 'ContentPlaceHolder1_ddlDestiStop'}).find_all('option')}

        origin_value = origin_stops.get(origin_name)
        desti_value = desti_stops.get(desti_name)

        if not origin_value or not desti_value or origin_value == desti_value:
            print("Invalid origin or destination stop.")
            return None

        # Step 2: Prepare and send the POST request
        post_data = {
            'ctl00$ContentPlaceHolder1$ddlOriginStop': origin_value,
            'ctl00$ContentPlaceHolder1$ddlDestiStop': desti_value,
            'ctl00$ContentPlaceHolder1$btnGetFare': 'Get Fare',
        }

        # Add hidden form fields from the initial GET request
        for hidden_input in get_soup.find_all('input', {'type': 'hidden'}):
            post_data[hidden_input.get('name')] = hidden_input.get('value')

        post_response = requests.post(url, data=post_data, verify=False)
        post_soup = BeautifulSoup(post_response.text, 'html.parser')

        # Step 3: Parse the fare details from the response
        fare_table = post_soup.find('table', class_='table table-bordered')

        if not fare_table:
            print("Could not find the fare table after postback.")
            return None

        headers = [th.text.strip() for th in fare_table.find(
            'thead').find_all('th') if th.text.strip()]
        extracted_fare = {}
        for row in fare_table.find('tbody').find_all('tr'):
            row_header = row.find('th').text.strip()
            cells = [td.text.strip() for td in row.find_all('td')]

            if len(cells) == len(headers) - 1:
                row_data = {}
                for i in range(len(cells)):
                    row_data[headers[i+1]] = cells[i]
                extracted_fare[row_header] = row_data

        return extracted_fare

    except requests.exceptions.RequestException as e:
        print(f"An error occurred while fetching the webpage: {e}")
        return None
    except Exception as e:
        print(f"An error occurred during parsing: {e}")
        return None


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
