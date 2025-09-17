from quart import Quart
from quart_cors import cors
from config import config
from routes import api as api_blueprint


def create_app():
    app = Quart(__name__)

    app.config.from_object(config)

    cors(
        app,
        allow_credentials=True,
        allow_headers=["Content-Type", "Authorization",
                       "Access-Control-Allow-Origin"],
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_origin="https://suratstlk.onrender.com",
    )

    app.register_blueprint(api_blueprint)

    return app


app = create_app()

# if __name__ == "__main__":
#     app.run(debug=True)
