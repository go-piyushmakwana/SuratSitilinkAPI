from quart import Blueprint, request, jsonify, g
import datetime
import jwt
from auth import jwt_required
from config import config
import services as srv

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
        email, displayName, photoURL, providerId, password = data.get('email'), data.get(
            'displayName'), data.get('photoURL'), data.get('providerId'), data.get('password')

        if not email:
            return jsonify({"error": "Missing required fields"}), 400
        if await srv.check_user_async(email):
            return jsonify({"error": "Email already exists."}), 409

        success, message = await srv.create_user_async(
            name=displayName, email=email, password=password, photoURL=photoURL, providerId=providerId
        )
        return (jsonify({"success": True, "message": message}), 201) if success else (jsonify({"error": message}), 500)
    except Exception as e:
        print(f"Error during user registration: {e}")
        return jsonify({"error": "An internal server error occurred."}), 500


@api.route('/login', methods=['POST'])
async def api_login():
    data = await request.get_json()
    email, password = data.get('email'), data.get('password')
    if not all([email, password]):
        return jsonify({"error": "Missing email or password"}), 400

    if await srv.validate_user_async(email, password):
        # Generate a JWT token
        payload = {
            'email': email,
            'exp': datetime.datetime.now(datetime.timezone.utc) + config.JWT_EXPIRATION_DELTA
        }
        token = jwt.encode(payload, config.JWT_SECRET_KEY, algorithm='HS256')
        return jsonify({"success": True, "token": token}), 200
    else:
        return jsonify({"error": "Invalid email or password"}), 401


@api.route('/routes', methods=['GET'])
async def api_get_routes():
    routes = await srv.get_all_routes_async()
    return jsonify({"routes": routes}), 200


@api.route('/stops', methods=['GET'])
async def api_get_stops():
    stops = await srv.get_all_stops_async()
    return jsonify({"stops": stops}), 200

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
