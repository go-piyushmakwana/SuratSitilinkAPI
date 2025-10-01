from quart import Blueprint, request, jsonify, g
import services as srv
import jwt
from config import config
from datetime import datetime, timezone
from auth import jwt_required
from utils import generate_jwt

api = Blueprint('api', __name__, url_prefix='/api/v2')


def serialize_document(doc):
    if '_id' in doc:
        doc['_id'] = str(doc['_id'])
    return doc


@api.route('/')
async def index():
    return jsonify({"message": "Welcome to the Surat Sitilink API!"})


@api.route('/register_user', methods=['POST'])
async def api_register():
    try:
        data = await request.get_json()
        email, name, password, gender, dob = data.get('email'), data.get(
            'name'), data.get('password'), data.get('gender'), data.get('dob')
        photo = data.get('photo')

        if not email or not name or not password:
            return jsonify({"error": "Missing required fields"}), 400

        if await srv.check_user_async(email):
            return jsonify({"error": "Email already exists."}), 409

        success, message = await srv.create_user_async(
            email=email, name=name, password=password, photo=photo, gender=gender, dob=dob
        )
        if success:
            # Generate JWT on successful registration
            payload = {
                'email': email,
                'exp': datetime.now(timezone.utc) + config.JWT_EXPIRATION_DELTA
            }
            token = jwt.encode(
                payload, config.JWT_SECRET_KEY, algorithm='HS256')
            return jsonify({
                "success": True,
                "message": message,
                "token": token
            }), 201
        else:
            return jsonify({"error": message}), 500
    except Exception as e:
        print(f"Error during user registration: {e}")
        return jsonify({"error": "An internal server error occurred."}), 500


@api.route('/login_user', methods=['POST'])
async def api_login():
    try:
        data = await request.get_json()
        email, password = data.get('email'), data.get('password')

        if not email or not password:
            return jsonify({"error": "Missing email or password"}), 400

        # Use the updated authenticate_user service function
        success, result = await srv.authenticate_user(email, password)

        if success:
            user = result
            token = generate_jwt(user)
            return jsonify({"success": True, "message": "Login successful", "token": token}), 200
        else:
            error_message = result  # The error message string

            if error_message == "Incorrect password.":
                # User exists, but password is wrong
                return jsonify({"error": "Password is wrong."}), 401
            elif error_message == "User not found.":
                # User does not exist
                return jsonify({"error": "Credentials not available or invalid."}), 401
            else:
                # Other authentication failures
                return jsonify({"error": "Authentication failed."}), 401

    except Exception as e:
        print(f"Error during user login: {e}")
        return jsonify({"error": "An internal server error occurred."}), 500


@api.route('/forgot_password', methods=['POST'])
async def api_forgot_password():
    """Endpoint for initiating a password reset process, requiring email and birthdate."""
    try:
        data = await request.get_json()
        email = data.get('email')
        birthdate = data.get('birthdate')

        if not email or not birthdate:
            return jsonify({"error": "Missing email or birthdate"}), 400

        # Pass both email and birthdate to the service function
        _, message = await srv.generate_password_reset_token_async(email, birthdate)

        # Return a generic success message to prevent user enumeration
        return jsonify({"success": True, "message": message}), 200

    except Exception as e:
        print(f"Error during forgot password request: {e}")
        return jsonify({"error": "An internal server error occurred."}), 500


@api.route('/check_user', methods=['GET'])
async def api_check_user():
    try:
        email = request.args.get('email')
        if not email:
            return jsonify({"error": "Email parameter is missing"}), 400

        user_exists = await srv.check_user_async(email)

        return jsonify({"email_exists": user_exists}), 200
    except Exception as e:
        print(f"Error checking user existence: {e}")
        return jsonify({"error": "An internal server error occurred."}), 500


@api.route('/current_user', methods=['GET'])
@jwt_required
async def api_current_login_user():
    try:
        user_email = g.email
        user = await srv.get_user_by_email_async(user_email)
        if user:
            # Remove sensitive data like password hash before sending
            user.pop('password', None)
            return jsonify({"user": user}), 200
        else:
            return jsonify({"error": "User not found"}), 404
    except Exception as e:
        print(f"Error getting current user: {e}")
        return jsonify({"error": "An internal server error occurred."}), 500


@api.route('/delete_user', methods=['DELETE'])
@jwt_required
async def api_delete_current_user():
    try:
        user_email = g.email
        success, message = await srv.delete_user_async(user_email)
        return (jsonify({"success": True, "message": message}), 200) if success else (jsonify({"error": message}), 500)
    except Exception as e:
        print(f"Error during user deletion: {e}")
        return jsonify({"error": "An internal server error occurred."}), 500


@api.route('/book_ticket', methods=['POST'])
@jwt_required
async def api_book_ticket():
    try:
        data = await request.get_json()
        required_fields = ["origin", "destination", "service_no", "booking_date",
                           "journey_time", "passengers", "total_fare", "passengers_list", "sitilink_Id"]
        if not all(field in data for field in required_fields):
            return jsonify({"error": "Missing required fields"}), 400

        success, message = await srv.create_ticket_async(
            user_email=g.email,
            ticket_data=data
        )

        if success:
            return jsonify({"success": True, "message": message}), 201
        else:
            return jsonify({"error": message}), 500
    except Exception as e:
        print(f"Error during ticket booking: {e}")
        return jsonify({"error": "An internal server error occurred."}), 500


@api.route('/update_user', methods=['PUT'])
@jwt_required
async def api_update_current_user():
    try:
        data = await request.get_json()
        user_email = g.email
        name = data.get('name')
        photo = data.get('photo')
        bio = data.get('bio')
        url = data.get('url')
        password = data.get('password')

        success, message = await srv.update_user_async(
            email=user_email, name=name, photo=photo, password=password, bio=bio, url=url
        )
        return (jsonify({"success": True, "message": message}), 200) if success else (jsonify({"error": message}), 500)
    except Exception as e:
        print(f"Error during user update: {e}")
        return jsonify({"error": "An internal server error occurred."}), 500


@api.route('/user/password', methods=['PUT'])
@jwt_required
async def api_update_password():
    try:
        data = await request.get_json()
        old_password = data.get('old_password')
        new_password = data.get('new_password')
        user_email = g.email

        if not old_password or not new_password:
            return jsonify({"error": "Missing old_password or new_password"}), 400

        # Basic password length validation
        if len(new_password) < 6:
            return jsonify({"error": "New password must be at least 6 characters long."}), 400

        success, message = await srv.update_password_async(
            email=user_email, old_password=old_password, new_password=new_password
        )

        if success:
            return jsonify({"success": True, "message": message}), 200
        else:
            # If authentication failed (incorrect old password), return 401 Unauthorized
            if message == "Incorrect old password.":
                return jsonify({"error": message}), 401
            return jsonify({"error": message}), 500

    except Exception as e:
        print(f"Error during password update API: {e}")
        return jsonify({"error": "An internal server error occurred."}), 500

# Surat Sitilink API Endpoints


@api.route('/gallery', methods=['GET'])
async def api_get_gallery():
    images = await srv.get_sitilink_gallery()
    return jsonify({"gallery": images}), 200


@api.route('/fare_prices', methods=['GET'])
async def api_get_fare_prices():
    origin = request.args.get('origin')
    destination = request.args.get('destination')
    if not origin or not destination:
        return jsonify({"error": "Both 'origin' and 'destination' query parameters are required."}), 400

    fare_details = await srv.get_fare_details_async(origin, destination)
    if fare_details:
        return jsonify(fare_details), 200
    else:
        return jsonify({"error": "Could not retrieve fare details."}), 500


@api.route('/stops', methods=['GET'])
async def api_get_stops():
    stops = await srv.get_all_stops_async()
    return jsonify({"stops": stops}), 200


@api.route('/routes', methods=['GET'])
async def api_get_routes():
    routes = await srv.get_all_routes_async()
    return jsonify({"routes": routes}), 200


@api.route('/routes/<route_id>', methods=['GET'])
async def api_get_route_by_id(route_id):
    try:
        route = await srv.get_route_by_id_async(route_id)
        if route:
            return jsonify(route), 200
        else:
            return jsonify({"error": "Route not found."}), 404
    except Exception as e:
        print(f"Error in api_get_route_by_id: {e}")
        return jsonify({"error": "An internal server error occurred."}), 500


@api.route('/tickets/history', methods=['GET'])
@jwt_required
async def api_get_tickets_history():
    try:
        user_email = g.email
        tickets = await srv.get_tickets_history_async(user_email)

        # Serialize the tickets to convert ObjectId to string
        serialized_tickets = [serialize_document(ticket) for ticket in tickets]

        return jsonify({"tickets": serialized_tickets}), 200
    except Exception as e:
        print(f"Error fetching ticket history: {e}")
        return jsonify({"error": "An internal server error occurred."}), 500


@api.route('/contact_us', methods=['POST'])
async def api_contact_us():
    try:
        data = await request.get_json()
        name = data.get('name')
        email = data.get('email')
        subject = data.get('subject')
        message = data.get('message')
        time = data.get('time')

        if not name or not email or not subject or not message or not time:
            return jsonify({"error": "Missing required fields"}), 400

        success, msg = await srv.contact_us(name, email, subject, message, time)
        if success:
            return jsonify({"success": True, "message": msg}), 201
        else:
            return jsonify({"error": msg}), 500
    except Exception as e:
        print(f"Error during message submission: {e}")
        return jsonify({"error": "An internal server error occurred."}), 500


@api.route('/check_ticket', methods=['POST'])
async def api_check_ticket():
    """
    Endpoint to validate a ticket using Sitilink ID, origin, and destination.
    Returns the full ticket details if all fields match a record.
    """
    try:
        data = await request.get_json()
        sitilink_id = data.get('sitilink_Id')
        origin = data.get('origin')
        destination = data.get('destination')

        if not all([sitilink_id, origin, destination]):
            return jsonify({"error": "Missing sitilink_id, origin, or destination in request body."}), 400

        # Call the new service function to validate the ticket
        ticket = await srv.validate_ticket_async(sitilink_id, origin, destination)

        if ticket:
            # If the ticket is found, return the full details, serialized
            return jsonify({"success": True, "ticket": serialize_document(ticket)}), 200
        else:
            # If no matching ticket is found
            return jsonify({"error": "Invalid ticket details or ticket not found."}), 404

    except Exception as e:
        print(f"Error checking ticket: {e}")
        return jsonify({"error": "An internal server error occurred during ticket check."}), 500


@api.route('/downloads', methods=['GET'])
async def api_get_downloads():
    try:
        downloads = await srv.get_downloads_async()
        return jsonify({"downloads": downloads}), 200
    except Exception as e:
        print(f"Error fetching downloads: {e}")
        return jsonify({"error": "An internal server error occurred."}), 500


@api.route('/find_routes', methods=['GET'])
async def api_find_routes():
    origin = request.args.get('origin')
    destination = request.args.get('destination')
    if not origin or not destination:
        return jsonify({"error": "Both 'origin' and 'destination' query parameters are required."}), 400

    routes = await srv.find_routes_between_stops_async(origin, destination)
    if routes:
        return jsonify({"routes": routes}), 200
    else:
        return jsonify({"message": "No routes found between the specified stops."}), 404


@api.route('/tickets/<ticket_id>', methods=['DELETE'])
@jwt_required
async def api_delete_ticket(ticket_id):
    try:
        user_email = g.email

        # Call the service function to attempt deletion
        success, message = await srv.delete_ticket_async(user_email, ticket_id)

        if success:
            return jsonify({"success": True, "message": message}), 200
        else:
            # Assign appropriate HTTP status codes based on the error message
            status_code = 500
            if "not found" in message:
                status_code = 404
            elif "unauthorized" in message:
                status_code = 403
            elif "Invalid ticket ID" in message:
                status_code = 400

            return jsonify({"error": message}), status_code

    except Exception as e:
        print(f"Error deleting ticket: {e}")
        return jsonify({"error": "An internal server error occurred."}), 500
