#!/usr/bin/python
# -*- coding: utf-8 -*-

from flask_restx import Api
from api.handlers.UserHandlers import ns as user_ns


def generate_routes(api):
    """
    Registers all namespaces with the provided API instance.
    """
    # Register the user namespace
    api.add_namespace(user_ns)
