#!/usr/bin/python
# -*- coding: utf-8 -*-

import logging
from datetime import datetime

from flask import request, current_app as app, url_for
from flask_mail import Mail, Message
from flask_restx import Resource
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature

from api.conf.auth import auth, refresh_jwt, jwt
from api.database.database import db
from api.models.models import Blacklist, Roles, User
from api.roles import role_required
from api.schemas.schemas import BaseUserSchema, UserSchema
from api.error.errors import INVALID_INPUT_422, ALREADY_EXIST, UNAUTHORIZED, DOES_NOT_EXIST

from argon2 import PasswordHasher


class Index(Resource):
    @staticmethod
    def get():
        return "Hello Flask RestX Example!"


class Register(Resource):
    @staticmethod
    def post():
        try:
            username = request.json.get("username").strip()
            password = request.json.get("password").strip()
            email = request.json.get("email").strip()

            ph = PasswordHasher()
            password = ph.hash(password)

            user_role = request.json.get("role", Roles.USER.name.lower()).strip()
            phone = request.json.get("phone", None)
            address = request.json.get("address", None)

            if user_role == Roles.PROPERTY_AGENT.name.lower():
                agency_name = request.json.get("agency_name", None)
                area_of_operation = request.json.get("area", None)

        except Exception as e:
            logging.warning(f"Invalid input: {e}")
            return INVALID_INPUT_422

        if not username or not password or not email:
            return INVALID_INPUT_422

        user = User.query.filter_by(email=email).first()
        if user:
            return ALREADY_EXIST

        if user_role not in [role.name.lower() for role in Roles]:
            return INVALID_INPUT_422

        user = User(
            username=username,
            password=password,
            email=email,
            user_role=user_role,
            phone=phone,
            address=address,
            agency_name=agency_name if user_role == Roles.PROPERTY_AGENT.name.lower() else None,
            area_of_operation=area_of_operation if user_role == Roles.PROPERTY_AGENT.name.lower() else None,
        )

        db.session.add(user)
        db.session.commit()

        return {"status": "registration completed."}


class Login(Resource):
    @staticmethod
    def post():
        try:
            email = request.json.get("email").strip()
            password = request.json.get("password").strip()

        except Exception as e:
            logging.warning(f"Invalid input: {e}")
            return INVALID_INPUT_422

        if not email or not password:
            return INVALID_INPUT_422

        user = User.query.filter_by(email=email).first()
        if not user:
            return UNAUTHORIZED

        ph = PasswordHasher()
        try:
            ph.verify(user.password, password)
        except:
            return UNAUTHORIZED

        access_token = user.generate_auth_token(user.user_role)
        refresh_token = refresh_jwt.dumps({"email": email})

        return {
            "access_token": access_token.decode(),
            "refresh_token": refresh_token.decode(),
        }


class Logout(Resource):
    @staticmethod
    @auth.login_required
    def post():
        _, access_token = request.headers["Authorization"].split(None, 1)

        if Blacklist.query.filter_by(access_token=access_token).first():
            return {"status": "already invalidated", "access_token": access_token}

        blacklist_token = Blacklist(access_token=access_token)
        db.session.add(blacklist_token)
        db.session.commit()

        return {"status": "invalidated", "access_token": access_token}


class RefreshToken(Resource):
    @staticmethod
    def post():
        try:
            refresh_token = request.json.get("refresh_token")

            if Blacklist.query.filter_by(refresh_token=refresh_token).first():
                return {"status": "invalidated"}, 401

            data = refresh_jwt.loads(refresh_token)

            user = User.query.filter_by(email=data["email"]).first()
            if not user:
                return {"status": "User not found"}, 404

            new_token = user.generate_auth_token()
            return {"access_token": new_token.decode()}

        except Exception as e:
            logging.error(f"Error refreshing token: {e}")
            return {"status": "Invalid or expired token"}, 401


class ResetPassword(Resource):
    @auth.login_required
    def post(self):
        mail = Mail(app)
        email = request.json.get("email")
        user = User.query.filter_by(email=email).first()

        if not user:
            return {"status": "User not found"}, 404

        s = URLSafeTimedSerializer(app.config["SECRET_KEY"])
        token = s.dumps(email, salt=app.config["SECURITY_PASSWORD_SALT"])

        link = url_for("reset_token", token=token, _external=True)
        msg = Message("Password Reset", sender="your@email.com", recipients=[email])
        msg.body = f"Your password reset link is {link}"
        mail.send(msg)

        return {"status": "Password reset email sent"}, 200

    @auth.login_required
    def put(self):
        token = request.json.get("token")
        new_pass = request.json.get("new_pass")
        s = URLSafeTimedSerializer(app.config["SECRET_KEY"])

        try:
            email = s.loads(token, salt=app.config["SECURITY_PASSWORD_SALT"], max_age=3600)
        except (SignatureExpired, BadSignature):
            return {"status": "Invalid or expired token"}, 401

        user = User.query.filter_by(email=email).first()
        if not user:
            return {"status": "User not found"}, 404

        ph = PasswordHasher()
        user.password = ph.hash(new_pass)
        db.session.commit()

        return {"status": "Password updated successfully"}, 200


class Address(Resource):
    @auth.login_required
    def get(self):
        _, access_token = request.headers["Authorization"].split(None, 1)
        data = jwt.loads(access_token)

        user = User.query.filter_by(email=data["email"]).first()
        if not user:
            return DOES_NOT_EXIST

        return {"address": user.address}


class UserInfo(Resource):
    @auth.login_required
    def get(self):
        _, access_token = request.headers["Authorization"].split(None, 1)
        data = jwt.loads(access_token)

        user = User.query.filter_by(email=data["email"]).first()
        if not user:
            return DOES_NOT_EXIST

        return {
            "username": user.username,
            "email": user.email,
            "phone": user.phone,
            "address": user.address,
            "agency_name": user.agency_name,
            "area_of_operation": user.area_of_operation,
        }


class UsersData(Resource):
    @auth.login_required
    @role_required.permission(2)
    def get(self):
        try:
            usernames = request.args.get("usernames", "").split(",")
            emails = request.args.get("emails", "").split(",")
            start_date = datetime.strptime(request.args.get("start_date", "01.01.1900"), "%d.%m.%Y")
            end_date = datetime.strptime(request.args.get("end_date", datetime.now().strftime("%d.%m.%Y")), "%d.%m.%Y")

            users = (
                User.query.filter(User.username.in_(usernames))
                .filter(User.email.in_(emails))
                .filter(User.created.between(start_date, end_date))
                .all()
            )

            user_schema = BaseUserSchema(many=True) if request.args.get("full") else UserSchema(many=True)
            data = user_schema.dump(users)

            return data

        except Exception as e:
            logging.error(e)
            return INVALID_INPUT_422
