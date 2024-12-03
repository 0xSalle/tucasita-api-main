# -*- coding: utf-8 -*-

from flask import request
from flask_restx import Namespace, Resource, fields
from api.conf.auth import auth
from api.models.models import User
from api.error.errors import INVALID_INPUT_422, UNAUTHORIZED

# Create a namespace for Swagger
ns = Namespace("v1", description="API v1 routes")

# Models for Swagger
register_model = ns.model("RegisterRequest", {
    "username": fields.String(required=True, description="The username", example="john_doe"),
    "email": fields.String(required=True, description="The user email", example="john_doe@example.com"),
    "password": fields.String(required=True, description="The user password", example="securepassword123"),
})

login_model = ns.model("LoginRequest", {
    "email": fields.String(required=True, description="The user email", example="user@example.com"),
    "password": fields.String(required=True, description="The user password", example="securepassword123"),
})

login_response_model = ns.model("LoginResponse", {
    "access_token": fields.String(description="JWT access token", example="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."),
    "refresh_token": fields.String(description="JWT refresh token", example="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."),
})

address_response_model = ns.model("AddressResponse", {
    "address": fields.String(description="User's address", example="123 Main St, Springfield"),
})


# Register resource
@ns.route("/auth/register")
class Register(Resource):
    @ns.expect(register_model)
    def post(self):
        """
        Register a new user
        """
        data = request.json
        if not data:
            return INVALID_INPUT_422
        # Simulate user creation
        return {"message": "User registered successfully"}, 201


# Login resource
@ns.route("/auth/login")
class Login(Resource):
    @ns.expect(login_model)
    @ns.marshal_with(login_response_model)
    def post(self):
        """
        Authenticate a user
        """
        data = request.json
        if not data:
            return INVALID_INPUT_422

        user = User.query.filter_by(email=data["email"]).first()
        if not user:
            return UNAUTHORIZED

        return {
            "access_token": "example_access_token",
            "refresh_token": "example_refresh_token",
        }


# Logout resource
@ns.route("/auth/logout")
class Logout(Resource):
    @auth.login_required
    def post(self):
        """
        Logout the current user
        """
        return {"message": "Logout successful"}, 200


# Refresh token resource
@ns.route("/auth/refresh")
class RefreshToken(Resource):
    def post(self):
        """
        Refresh the authentication token
        """
        return {"message": "Token refreshed successfully"}, 200


# Password reset resource
@ns.route("/auth/password_reset")
class ResetPassword(Resource):
    def post(self):
        """
        Send a password reset email
        """
        return {"message": "Password reset email sent"}, 200

    def put(self):
        """
        Update the password
        """
        return {"message": "Password updated successfully"}, 200


# Address resource
@ns.route("/address")
class Address(Resource):
    @auth.login_required
    @ns.marshal_with(address_response_model)
    def get(self):
        """
        Get the address of the logged-in user
        """
        return {"address": "123 Main St, Springfield"}


# User info resource
@ns.route("/user_info")
class UserInfo(Resource):
    def get(self):
        """
        Get user information
        """
        return {
            "username": "john_doe",
            "email": "john_doe@example.com",
            "phone": "+123456789",
            "address": "123 Main St, Springfield",
            "agency_name": "Real Estate Inc.",
            "area_of_operation": "Springfield",
        }
# Users data resource
@ns.route("/users")
class UsersData(Resource):
    @auth.login_required
    def get(self):
        """
        Get data of all users (Admin only)
        """
        # Simulate fetching user data
        return [
            {
                "username": "john_doe",
                "email": "john_doe@example.com",
                "created_at": "2023-01-01T12:00:00",
            },
            {
                "username": "jane_doe",
                "email": "jane_doe@example.com",
                "created_at": "2023-02-01T12:00:00",
            },
        ]
