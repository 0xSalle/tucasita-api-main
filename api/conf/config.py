#!/usr/bin/python
# -*- coding: utf-8 -*-

import os
from dotenv import load_dotenv

load_dotenv()

basedir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

# Create a database in project and get it's path.
SQLALCHEMY_DATABASE_URI = "sqlite:///" + os.path.join(basedir, "test.db")

# Get debug status
debug_status = True \
    if (os.getenv("DEBUGSTATUS").capitalize() in ('True', '1')) \
    else False

# Get application port
try:
    port = int(os.getenv('PORT'))
except:
    logging.info('Port environment variable not found, defaulting to 5000')
    port = 5000
