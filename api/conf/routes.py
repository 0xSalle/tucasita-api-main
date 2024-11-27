#!/usr/bin/python
# -*- coding: utf-8 -*-

from flask_restful import Api
from api.conf.config import debug_status

from api.handlers.UserHandlers import (
    Address,
    Index,
    Login,
    Logout,
    RefreshToken,
    Register,
    ResetPassword,
    UsersData,
    UserInfo)


def generate_routes(app):

    # Create api.
    api = Api(app)

    # Add all routes resources.
    
    # Register.
    api.add_resource(Register, "/v1/auth/register")

    # Login.
    api.add_resource(Login, "/v1/auth/login")

    # Logout.
    api.add_resource(Logout, "/v1/auth/logout")

    # Refresh token.
    api.add_resource(RefreshToken, "/v1/auth/refresh")

    # Password reset. Not forgot.
    api.add_resource(ResetPassword, "/v1/auth/password_reset")

    # Return address of logged user.
    api.add_resource(Address, "/address")

    # Return logged user information
    api.add_resource(UserInfo, "/user_info")

    # Get users page with admin permissions.
    if (debug_status):
        api.add_resource(UsersData, "/users")
