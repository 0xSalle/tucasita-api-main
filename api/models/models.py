#!/usr/bin/python
# -*- coding: utf-8 -*-

import logging
from datetime import datetime
from enum import Enum

from flask import g

from api.conf.auth import auth, jwt
from api.database.database import db


class Roles(Enum):
    USER = 0
    ADMIN = 1
    SA = 2 # super admin
    PROPERTY_AGENT = 3

class User(db.Model):

    # Generates default class name for table. For changing use
    # __tablename__ = 'users'

    # User id.
    id = db.Column(db.Integer, primary_key=True)

    # User name.
    username = db.Column(db.String(length=80))

    # User password.
    password = db.Column(db.String(length=80))

    # User email address.
    email = db.Column(db.String(length=80))

    # User phone
    phone = db.Column(db.String(length=12))

    # User address
    address = db.Column(db.String(length=180))

    # Agency name, only for property agents
    agency_name = db.Column(db.String(length=80))

    # Area of operation (neighborhood), only for property agents
    area_of_operation = db.Column(db.String(length=80))

    # Creation time for user.
    created = db.Column(db.DateTime, default=datetime.utcnow)

    # Unless otherwise stated default role is user, which is a buyer.
    user_role = db.Column(db.String, default=Roles.USER.name.lower())

    # Generates auth token.
    def generate_auth_token(self, permission_level):

        token = jwt.dumps({"email": self.email, "admin": permission_level})
        # Return normal user flag.
        return token

    # Generates a new access token from refresh token.
    @staticmethod
    @auth.verify_token
    def verify_auth_token(token):

        # Create a global none user.
        g.user = None

        try:
            # Load token.
            data = jwt.loads(token)

        except:
            # If any error return false.
            return False

        # Check if email and admin permission variables are in jwt.
        if "email" in data and "admin" in data:

            # Set email from jwt.
            g.user = data["email"]

            # Set admin permission from jwt.
            g.admin = data["admin"]

            # Return true.
            return True

        # If does not verified, return false.
        return False

    def __repr__(self):

        # This is only for representation how you want to see user information after query.
        return "<User(id='%s', name='%s', password='%s', email='%s', created='%s', phone='%s', address='%s', agency_name='%s', area_of_operation='%s')>" % (
            self.id,
            self.username,
            self.password,
            self.email,
            self.created,
            self.phone,
            self.address,
            self.agency_name,
            self.area_of_operation,
        )


class Blacklist(db.Model):

    # Generates default class name for table. For changing use
    # __tablename__ = 'users'

    # Blacklist id.
    id = db.Column(db.Integer, primary_key=True)

    # Blacklist invalidated refresh tokens.
    access_token = db.Column(db.String(length=255))

    def __repr__(self):

        # This is only for representation how you want to see refresh tokens after query.
        return "<User(id='%s', access_token='%s', status='invalidated.')>" % (
            self.id,
            self.access_token
        )
