#!/usr/bin/python
# -*- coding: utf-8 -*-

import logging
import os

from flask import Flask

from api.conf.config import SQLALCHEMY_DATABASE_URI
from api.conf.routes import generate_routes
from api.database.database import db
from api.db_initializer.db_initializer import create_admin_user, create_super_admin, create_test_user, create_test_property_agent
from api.conf.config import debug_status, port

def create_app():

    # Create a flask app.
    app = Flask(__name__)

    # Set debug true for catching the errors.
    app.config['DEBUG'] = debug_status

    # Set database url.
    app.config['SQLALCHEMY_DATABASE_URI'] = SQLALCHEMY_DATABASE_URI

    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True

    # Set application port
    app.config['PORT'] = port

    # Generate routes.
    generate_routes(app)

    # Database initialize with app.
    db.init_app(app)

    # Check if there is no database.
    if not os.path.exists(SQLALCHEMY_DATABASE_URI):

        # New db app if no database.
        db.app = app

        # Create all database tables.
        db.create_all()

        # Create default super admin user in database.
        create_super_admin()

        # Create default admin user in database.
        create_admin_user()

        # Create default test user in database.
        create_test_user()

        # Create default property agent user in database
        create_test_property_agent()

    # Return app.
    return app


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    
    # Create app.
    app = create_app()

    # Run app. For production use another web server.
    # Set debug and use_reloader parameters as False.
    app.run(port=port, debug=debug_status, host='localhost', use_reloader=True)
