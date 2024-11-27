#!/usr/bin/python
# -*- coding: utf-8 -*-

import logging, json
from datetime import datetime

from flask import g, request
from flask_restful import Resource

import api.error.errors as error
from api.conf.auth import auth, refresh_jwt, jwt
from api.database.database import db
from api.models.models import Blacklist, Roles, User
from api.roles import role_required
from api.schemas.schemas import BaseUserSchema, UserSchema
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from flask_mail import Mail, Message
from flask import current_app as app, request, url_for

from argon2 import PasswordHasher

class Index(Resource):
    @staticmethod
    def get():
        return "Hello Flask Restful Example!"


class Register(Resource):
    @staticmethod
    def post():

        try:
            #logging.info("Input: %s", request.json)
            # Mandatory attributes: username, password and email.
            username, password, email = (
                request.json.get("username").strip(),
                request.json.get("password").strip(),
                request.json.get("email").strip(),
            )

            # Hash password
            ph = PasswordHasher()
            password = ph.hash(password)
            
            # Optional attributes
            user_role = request.json.get("role").strip() if request.json.get("role") else Roles.USER.name.lower()
            phone = request.json.get("phone").strip() if request.json.get("phone") else None
            address = request.json.get("address").strip() if request.json.get("address") else None
            if user_role == Roles.PROPERTY_AGENT.name.lower():
                agency_name = request.json.get("agency_name").strip() if request.json.get("agency_name") else None
                area_of_operation = request.json.get("area").strip() if request.json.get("area") else None
        
        except Exception as why:

            # Log input strip or etc. errors.
            logging.warn("Username, password, email or role is wrong. " + str(why))

            # Return invalid input error.
            return error.INVALID_INPUT_422

        # Check if any field is none.
        if username is None or password is None or email is None:
            logging.info("Username, password or email is empty.")
            return error.INVALID_INPUT_422

        # Attempt to fetch existent user
        user = User.query.filter_by(email=email).first()

        # Check if user already exists
        if user is not None:
            return error.ALREADY_EXIST

        # Check if roles is valid
        role_names = [role.name.lower() for role in Roles]
        if user_role not in role_names:
            logging.warn("Role %s is not valid.", user_role)
            return error.INVALID_INPUT_422

        # Create a new user.
        user = User(username=username,
                    password=password,
                    email=email,
                    user_role=user_role,
                    phone=phone,
                    address=address,
                    agency_name=agency_name,
                    area_of_operation=area_of_operation)

        # Add user to session.
        db.session.add(user)

        # Commit session.
        db.session.commit()

        # Return success if registration is completed.
        return {"status": "registration completed."}


class Login(Resource):
    @staticmethod
    def post():

        # Password hash helper
        ph = PasswordHasher()

        try:
            # Get user email and password.
            email, password = (
                request.json.get("email").strip(),
                request.json.get("password").strip(),
            )

        except Exception as why:

            # Log input strip or etc. errors.
            logging.info("Email or password is wrong. " + str(why))

            # Return invalid input error.
            return error.INVALID_INPUT_422

        # Check if user information is none.
        if email is None or password is None:
            logging.info("Email or password is empty.")
            return error.INVALID_INPUT_422

        # Get user if it is existed.
        user = User.query.filter_by(email=email).first()

        # Check if user is not existed.
        if user is None:
            return error.UNAUTHORIZED

        # Check if password is correct
        try:
            assert ph.verify(user.password, password)
        except:
            return error.UNAUTHORIZED

        if user.user_role == Roles.USER.name.lower():

            access_token = user.generate_auth_token(Roles.USER.value)

        # If user is admin.
        elif user.user_role == Roles.ADMIN.name.lower():
            access_token = user.generate_auth_token(Roles.ADMIN.value)

        # If user is super admin.
        elif user.user_role == Roles.SA.name.lower():
            access_token = user.generate_auth_token(Roles.SA.value)

        # If user is property agent.
        elif user.user_role == Roles.PROPERTY_AGENT.name.lower():
            access_token = user.generate_auth_token(Roles.PROPERTY_AGENT.value)

        else:
            logging.info("User role is not defined.")
            return error.INVALID_INPUT_422

        # Generate refresh token.
        refresh_token = refresh_jwt.dumps({"email": email})

        # Return access token and refresh token.
        return {
            "access_token": access_token.decode(),
            "refresh_token": refresh_token.decode(),
        }


class Logout(Resource):
    @staticmethod
    @auth.login_required
    def post():

        # Get access token.
        _, access_token = request.headers["Authorization"].split(None, 1)

        # Get refresh token.
        # refresh_token = request.json.get("refresh_token")

        # Get if the refresh token is in blacklist
        ref = Blacklist.query.filter_by(access_token=access_token).first()

        # Check refresh token is existed.
        if ref is not None:
            return {"status": "already invalidated", "access_token": access_token}

        # Create a blacklist refresh token.
        blacklist_token = Blacklist(access_token=access_token)

        # Add refresh token to blacklist session refresh
        db.session.add(blacklist_token)

        # Commit session.
        db.session.commit()

        # Return status of refresh token.
        return {"status": "invalidated", "access_token": access_token}


class RefreshToken(Resource):
    @staticmethod
    def post():

        # Get refresh token.
        refresh_token = request.json.get("refresh_token")

        # Get if the refresh token is in blacklist.
        ref = Blacklist.query.filter_by(refresh_token=refresh_token).first()

        # Check refresh token is existed.
        if ref is not None:

            # Return invalidated token.
            return {"status": "invalidated"}

        try:
            # Generate new token.
            data = refresh_jwt.loads(refresh_token)

        except Exception as why:
            # Log the error.
            logging.error(why)

            # If it does not generated return false.
            return False

        # Create user not to add db. For generating token.
        user = User(email=data["email"])

        # New token generate.
        token = user.generate_auth_token(False)

        # Return new access token.
        return {"access_token": token}


class ResetPassword(Resource):
    @auth.login_required
    @role_required.permission(1)
    def post(self):
        mail = Mail(app)

        # Step 1: User requests password reset
        email = request.json.get("email")
        user = User.query.filter_by(email=email).first()
        if not user:
            return {"status": "User not found"}, 404

        # Generate a reset token
        s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
        token = s.dumps(email, salt=app.config['SECURITY_PASSWORD_SALT'])

        # Send email with reset token
        link = url_for('reset_token', token=token, _external=True)
        msg = Message("Password Reset", sender="your@email.com", recipients=[email])
        msg.body = f"Your password reset link is {link}"
        mail.send(msg)

        return {"status": "Password reset email sent"}, 200

    @auth.login_required
    def put(self):
        # Step 2: User submits new password with token
        token = request.json.get("token")
        new_pass = request.json.get("new_pass")
        s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

        try:
            email = s.loads(token, salt=app.config['SECURITY_PASSWORD_SALT'], max_age=3600)
        except (SignatureExpired, BadSignature):
            return {"status": "Invalid or expired token"}, 401

        user = User.query.filter_by(email=email).first()
        if not user:
            return {"status": "User not found"}, 404

        # Update password
        ph = PasswordHasher()
        user.password = ph.hash(new_pass)
        db.session.commit()

        return {"status": "Password updated successfully"}, 200


class Address(Resource):
    @auth.login_required
    def get(self):
        # Get authorization token
        _, access_token = request.headers["Authorization"].split(None, 1)
        data = jwt.loads(access_token)

        # Get user
        user = User.query.filter_by(email=data['email']).first()

        if not user:
            return error.DOES_NOT_EXIST

        return {'address': user.address}

class UserInfo(Resource):
    @auth.login_required
    def get(self):
        # Get authorization token
        _, access_token = request.headers["Authorization"].split(None, 1)
        data = jwt.loads(access_token)

        # Get user
        user = User.query.filter_by(email=data['email']).first()

        if not user:
            return error.DOES_NOT_EXIST

        return {
            'username': user.username,
            'email': user.email,
            'phone': user.phone,
            'address': user.address,
            'agency_name': user.agency_name,
            'area_of_operation': user.area_of_operation
        }

class UsersData(Resource):
    @auth.login_required
    @role_required.permission(2)
    def get(self):
        try:

            # Get usernames.
            usernames = (
                []
                if request.args.get("usernames") is None
                else request.args.get("usernames").split(",")
            )

            # Get emails.
            emails = (
                []
                if request.args.get("emails") is None
                else request.args.get("emails").split(",")
            )

            # Get start date.
            if request.args.get("start_date"):
                start_date = datetime.strptime(request.args.get("start_date"), "%d.%m.%Y")
            else:
                start_date = datetime.strptime("01.01.1900", "%d.%m.%Y")

            # Get end date.
            if request.args.get("end_date"):
                end_date = datetime.strptime(request.args.get("end_date"), "%d.%m.%Y")
            else:
                end_date = datetime.now()

            logging.info("Input Arguments: %s", request.args)

            # Filter users by usernames, emails and range of date.
            users = (
                User.query.filter(User.username.in_(usernames))
                .filter(User.email.in_(emails))
                .filter(User.created.between(start_date, end_date))
                .all()
            )

            if request.args.get("full"):
                    
                # Create user schema for serializing.
                user_schema = BaseUserSchema(many=True)

            else:
                # Create user schema for serializing.
                user_schema = UserSchema(many=True)

                # Get json data from db.
            data = user_schema.dump(users)

            # Return json data from db.
            return data

        except Exception as why:

            # Log the error.
            logging.error(why)

            # Return error.
            return error.INVALID_INPUT_422


# auth.login_required: Auth is necessary for this handler.
# role_required.permission: Role required user=0, admin=1 and super admin=2.


class DataUserRequired(Resource):
    @auth.login_required
    def get(self):

        return "Test user data."


class DataAdminRequired(Resource):
    @auth.login_required
    @role_required.permission(1)
    def get(self):

        return "Test admin data."


class DataSuperAdminRequired(Resource):
    @auth.login_required
    @role_required.permission(2)
    def get(self):

        return "Test super admin data."
