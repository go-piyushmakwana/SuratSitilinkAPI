
import warnings
import asyncio
import bcrypt
import requests
from bson import ObjectId
from bs4 import BeautifulSoup
from database import (
    bus_routes_collection,
    bus_stops_collection,
    users_collection,
    gallery_collection,
    tickets_collection,
    downloads_collection,
    contacts_collection,
    feedback_collection
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


async def delete_user_async(email: str) -> tuple[bool, str]:
    try:
        result = await users_collection.delete_one({"email": email})
        if result.deleted_count == 1:
            return True, "User deleted successfully."
        else:
            return False, "User not found."
    except Exception as e:
        print(f"Error while deleting user: {e}")
        return False, "An error occurred while deleting the user."


async def create_user_async(
    email: str,
    name: str,
    gender: str,
    dob: str,
    photo: str = None,
    password: str = None
) -> tuple[bool, str]:
    try:
        hashed_password = bcrypt.hashpw(
            password.encode('utf-8'), bcrypt.gensalt())
        user = {
            "email": email,
            "name": name,
            "birthdate": dob,
            "gender": gender,
            "photo": photo,
            "isEmailVerified": False,
            "bio": None,
            "url": None,
            "password": hashed_password
        }
        await users_collection.insert_one(user)
        return True, "User created successfully."
    except Exception as e:
        print(f"Error while creating user: {e}")
        return False, "An error occurred while creating the user."


async def update_user_async(email: str, name: str, photo: str, password: str, bio: str, url: str) -> tuple[bool, str]:
    try:
        update_fields = {}
        if name:
            update_fields["name"] = name
        if photo:
            update_fields["photo"] = photo
        if bio:
            update_fields["bio"] = bio
        if url:
            update_fields["url"] = url
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


async def update_password_async(email: str, old_password: str, new_password: str) -> tuple[bool, str]:
    """Authenticates the user with the old password and updates it with the new one."""
    try:
        user = await users_collection.find_one({"email": email})
        if not user:
            return False, "User not found."

        # Verify old password
        if not bcrypt.checkpw(old_password.encode('utf-8'), user['password']):
            return False, "Incorrect old password."

        # Hash and update new password
        hashed_password = bcrypt.hashpw(
            new_password.encode('utf-8'), bcrypt.gensalt()
        )

        result = await users_collection.update_one(
            {"email": email}, {"$set": {"password": hashed_password}}
        )

        if result.modified_count == 1:
            return True, "Password updated successfully."
        else:
            # Should only happen if user document disappeared between find and update, which is unlikely.
            return False, "Password update failed."

    except Exception as e:
        print(f"Error during password update: {e}")
        return False, f"An error occurred: {e}"


async def authenticate_user(email: str, password: str) -> tuple[bool, str | dict]:
    """
    Authenticates user and returns specific status messages for better login error handling.
    Returns: (True, user_dict) on success, (False, error_message_string) on failure.
    """
    try:
        user = await users_collection.find_one({"email": email})

        if not user:
            return False, "User not found."

        # User found, check password
        if user.get('password') and bcrypt.checkpw(password.encode('utf-8'), user['password']):
            # Success
            return True, user
        else:
            # Password check failed
            return False, "Incorrect password."

    except Exception as e:
        print(f"Error during user authentication: {e}")
        return False, "Authentication failed due to a server error."


async def generate_password_reset_token_async(email: str, birthdate: str) -> tuple[bool, str]:
    """
    Placeholder for a real-world password reset implementation, requiring email and birthdate verification.

    IMPORTANT: We return a generic success message regardless of user existence or match status 
    to prevent user enumeration attacks.
    """
    try:
        user = await users_collection.find_one({"email": email})

        is_match = False
        if user:
            stored_birthdate = user.get('birthdate')

            if stored_birthdate == birthdate:
                is_match = True

        # Only proceed with the token/email logic if both the email and birthdate match.
        if is_match:
            # Placeholder for actual token generation and email sending
            print(
                f"DEBUG: Password reset requested for {email} with correct birthdate. Token generation simulated.")

        return True, "Email and birthdate match a registered account."

    except Exception as e:
        print(f"Error generating password reset token: {e}")
        return False, "Failed to initiate password reset due to a server error."


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


async def get_sitilink_gallery():
    try:
        cursor = gallery_collection.find({}, {"_id": 0})
        return await cursor.to_list(None)
    except Exception as e:
        print(f"Error getting gallery images: {e}")
        return []


async def create_ticket_async(user_email, ticket_data):
    try:
        ticket_document = {
            "user_email": user_email,
            "origin": ticket_data.get("origin"),
            "destination": ticket_data.get("destination"),
            "service_no": ticket_data.get("service_no"),
            "booking_date": ticket_data.get("booking_date"),
            "journey_time": ticket_data.get("journey_time"),
            "passengers": ticket_data.get("passengers"),
            "total_fare": ticket_data.get("total_fare"),
            "passengers_list": ticket_data.get("passengers_list"),
            "sitilink_Id": ticket_data.get("sitilink_Id")
        }
        await tickets_collection.insert_one(ticket_document)
        return True, "Ticket booked successfully."
    except Exception as e:
        print(f"Error creating ticket: {e}")
        return False, "An error occurred while booking the ticket."


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


async def get_tickets_history_async(user_email: str):
    try:
        tickets = []
        cursor = tickets_collection.find({"user_email": user_email})
        for ticket in await cursor.to_list(length=None):
            tickets.append(ticket)
        return tickets
    except Exception as e:
        print(f"Error retrieving ticket history: {e}")
        return []


async def contact_us(name: str, email: str, subject: str, message: str, time: str) -> tuple[bool, str]:
    try:
        contact_us_doc = {
            "name": name,
            "email": email,
            "subject": subject,
            "message": message,
            "created_time": time
        }
        await contacts_collection.insert_one(contact_us_doc)
        return True, "Message submitted successfully."
    except Exception as e:
        print(f"Error submitting message: {e}")
        return False, "An error occurred while submitting message."


async def validate_ticket_async(sitilink_id: str, origin: str, destination: str):
    """
    Validates a ticket based on Sitilink ID, origin, and destination.
    """
    try:
        # Create the query to find a matching, active ticket
        query = {
            ""
            "sitilink_Id": sitilink_id,
            "origin": origin,
            "destination": destination
        }

        ticket = await tickets_collection.find_one(query)

        if ticket:
            # Exclude user_email for privacy if this were to be used by a conductor/public scanner
            # For this context, we return the full safe ticket data (assuming password hash is not stored here)
            return ticket

        return None

    except Exception as e:
        print(f"Error validating ticket: {e}")
        return None

async def get_downloads_async():
    try:
        cursor = downloads_collection.find({}, {"_id": 0})
        return await cursor.to_list(None)
    except Exception as e:
        print(f"Error getting downloads: {e}")
        return []

async def delete_ticket_async(user_email: str, ticket_id: str) -> tuple[bool, str]:
    """Deletes a ticket only if it belongs to the authenticated user."""
    try:
        # Convert the string ticket_id to ObjectId
        object_id = ObjectId(ticket_id)
    except Exception:
        return False, "Invalid ticket ID format."

    try:
        # Delete the ticket matching both the _id and the user_email for security
        result = await tickets_collection.delete_one({
            "_id": object_id,
            "user_email": user_email
        })

        if result.deleted_count == 1:
            return True, "Ticket deleted successfully."
        else:
            # Check if the ticket exists but belongs to someone else, or doesn't exist at all
            if await tickets_collection.find_one({"_id": object_id}):
                return False, "Ticket found, but unauthorized to delete."
            else:
                return False, "Ticket not found."

    except Exception as e:
        print(f"Error deleting ticket: {e}")
        return False, "An error occurred while deleting the ticket."
