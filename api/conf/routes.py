#!/usr/bin/python
# -*- coding: utf-8 -*-

from flask_restx import Api, Namespace, Resource
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
    UserInfo
)

def generate_routes(api):
    # Create a namespace for version 1 (v1) routes
    ns = Namespace("v1", description="API v1 routes")

    # Define routes for authentication
    ns.add_resource(Register, "/auth/register", endpoint="register")
    ns.add_resource(Login, "/auth/login", endpoint="login")
    ns.add_resource(Logout, "/auth/logout", endpoint="logout")
    ns.add_resource(RefreshToken, "/auth/refresh", endpoint="refresh")
    ns.add_resource(ResetPassword, "/auth/password_reset", endpoint="password_reset")

    # Define other routes
    ns.add_resource(Address, "/address", endpoint="address")
    ns.add_resource(UserInfo, "/user_info", endpoint="user_info")

    # Debug-only routes
    if debug_status:
        ns.add_resource(UsersData, "/users", endpoint="users")

    # Register the namespace with the API
    api.add_namespace(ns)
