from quart import Blueprint, request, jsonify, g
import services as srv
import jwt
from config import config
from datetime import datetime, timezone
from auth import jwt_required

api = Blueprint('api', __name__, url_prefix='/api/v2')


def serialize_document(doc):
    if '_id' in doc:
        doc['_id'] = str(doc['_id'])
    return doc


@api.route('/')
async def index():
    return jsonify({"message": "Welcome to the Surat Sitilink API!"})


@api.route('/register_user', methods=['POST'])
async def api_create_user():
    try:
        data = await request.get_json()
        email, name, password = data.get(
            'email'), data.get('name'), data.get('password')
        photo = data.get('photo')

        if not email or not name or not password:
            return jsonify({"error": "Missing required fields"}), 400

        if await srv.check_user_async(email):
            return jsonify({"error": "Email already exists."}), 409

        success, message = await srv.create_user_async(
            email=email, name=name, password=password, photo=photo
        )
        return (jsonify({"success": True, "message": message}), 201) if success else (jsonify({"error": message}), 500)
    except Exception as e:
        print(f"Error during user registration: {e}")
        return jsonify({"error": "An internal server error occurred."}), 500


@api.route('/signin', methods=['POST'])
async def api_signin_user():
    try:
        data = await request.get_json()
        email, password = data.get('email'), data.get('password')

        if not email or not password:
            return jsonify({"error": "Missing email or password"}), 400

        user = await srv.authenticate_user(email, password)
        if user:
            # Generate JWT
            payload = {
                'email': user['email'],
                'exp': datetime.now(timezone.utc) + config.JWT_EXPIRATION_DELTA
            }
            token = jwt.encode(
                payload, config.JWT_SECRET_KEY, algorithm='HS256')
            return jsonify({
                "success": True,
                "message": "Sign in successful.",
                "token": token
            }), 200
        else:
            return jsonify({"error": "Invalid email or password"}), 401
    except Exception as e:
        print(f"Error during sign-in: {e}")
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


@api.route('/update_user', methods=['PUT'])
@jwt_required
async def api_update_current_user():
    try:
        data = await request.get_json()
        user_email = g.email
        name = data.get('name')
        photo = data.get('photo')
        password = data.get('password')

        success, message = await srv.update_user_async(
            email=user_email, name=name, photo=photo, password=password
        )
        return (jsonify({"success": True, "message": message}), 200) if success else (jsonify({"error": message}), 500)
    except Exception as e:
        print(f"Error during user update: {e}")
        return jsonify({"error": "An internal server error occurred."}), 500

# Surat Sitilink API Endpoints


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
