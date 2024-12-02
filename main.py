#!/usr/bin/python
# -*- coding: utf-8 -*-

import logging
import os
from dotenv import load_dotenv
from flask import Flask
from flask_restx import Api

# Import configurations and modules
from api.conf.config import SQLALCHEMY_DATABASE_URI, debug_status, port
from api.conf.routes import generate_routes
from api.database.database import db
from api.db_initializer.db_initializer import (
    create_admin_user,
    create_super_admin,
    create_test_user,
    create_test_property_agent,
)

# Load environment variables from .env
load_dotenv()

def create_app():
    # Create a Flask app
    app = Flask(__name__)

    # Create an API object for Swagger documentation
    api = Api(
        app,
        version="1.0",
        title="My Flask API",
        description="A simple API with auto-generated OpenAPI documentation",
        doc="/api-docs",  # Swagger UI documentation endpoint
    )

    # Configure the app
    app.config["DEBUG"] = debug_status
    app.config["SQLALCHEMY_DATABASE_URI"] = SQLALCHEMY_DATABASE_URI
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    # Initialize database with the app
    db.init_app(app)

    # Check if the database exists
    database_file_path = SQLALCHEMY_DATABASE_URI.replace("sqlite:///", "")  # Adjust for SQLite
    if not os.path.exists(database_file_path):
        with app.app_context():
            # Create all database tables
            db.create_all()

            # Populate the database with default values
            create_super_admin()
            create_admin_user()
            create_test_user()
            create_test_property_agent()

    # Generate routes and register them with the API
    generate_routes(api)

    return app


if __name__ == "__main__":
    # Set up logging
    logging.basicConfig(level=logging.INFO)

    # Create the Flask app
    app = create_app()

    # Run the app (use a production-ready server like Gunicorn in production)
    app.run(port=port, debug=debug_status, host="0.0.0.0", use_reloader=False)
