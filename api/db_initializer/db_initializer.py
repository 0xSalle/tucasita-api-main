import logging
import os
from argon2 import PasswordHasher
from dotenv import load_dotenv

load_dotenv()

# Example of retrieving environment variables
superadmin_username = os.getenv("SUPERADMIN_USERNAME")
superadmin_password = os.getenv("SUPERADMIN_PASSWORD")

admin_username = os.getenv("ADMIN_USERNAME")
admin_password = os.getenv("ADMIN_PASSWORD")

user_username = os.getenv("USER_USERNAME")
user_password = os.getenv("USER_PASSWORD")

propertyagent_username = os.getenv("PROPERTYAGENT_USERNAME")
propertyagent_password = os.getenv("PROPERTYAGENT_PASSWORD")

ph = PasswordHasher()


from api.database.database import db
from api.models.models import User


def create_super_admin():

    # Check if admin is existed in db.
    user = User.query.filter_by(email="test_username").first()

    # If user is none.
    if user is None:

        # Create admin user if it does not existed.
        user = User(
            username=ph.hash(superadmin_username),
            password=ph.hash(superadmin_password),
            email="sa_email@example.com",
            user_role="sa",
        )

        # Add user to session.
        db.session.add(user)

        # Commit session.
        db.session.commit()

        # Print admin user status.
        logging.info("Super admin was set.")

    else:

        # Print admin user status.
        logging.info("Super admin already set.")


def create_admin_user():

    # Check if admin is existed in db.
    user = User.query.filter_by(email="admin").first()

    # If user is none.
    if user is None:

        # Create admin user if it does not existed.
        user = User(
            username=ph.hash(admin_username),
            password=ph.hash(admin_password),
            email="admin_email@example.com",
            user_role="admin",
        )

        # Add user to session.
        db.session.add(user)

        # Commit session.
        db.session.commit()

        # Print admin user status.
        logging.info("Admin was set.")

    else:
        # Print admin user status.
        logging.info("Admin already set.")


def create_test_user(
    username=ph.hash(user_username),
    password=ph.hash(user_password),
    email="test_email@example.com",
    user_role="user",
    phone="525555555555",
    address="Anillo Perif. Sur Manuel Gómez Morín 8585, Santa María Tequepexpan, 45604 San Pedro Tlaquepaque, Jal."
):

    # Check if admin is existed in db.
    user = User.query.filter_by(email="test_username").first()

    # If user is none.
    if user is None:

        # Create admin user if it does not existed.
        # user = User(username=username, password=password, email=email, user_role=user_role)
        user = User(
            username=username,
            password=password,
            email=email,
            user_role=user_role,
            phone=phone,
            address=address,
        )

        # Add user to session.
        db.session.add(user)

        # Commit session.
        db.session.commit()

        # Print admin user status.
        logging.info("Test user was set.")

        # Return user.
        return user

    else:

        # Print admin user status.
        logging.info("User already set.")

def create_test_property_agent(
    username=ph.hash(propertyagent_username),
    password=ph.hash(propertyagent_password),
    email="agent_email@example.com",
    user_role="property_agent",
    phone="523333333333",
    address="Evergreen 122, Americana, 45604 San Pedro Tlaquepaque, Jal.",
    agency_name="TuCasita Property Agency",
    area_of_operation="Tlaquepaque"
):
    # Check if agent user existed in db.
    user = User.query.filter_by(email="agent_username").first()

    # If user is none.
    if user is None:

        # Create admin user if it does not existed.

        user = User(
            username=username,
            password=password,
            email=email,
            user_role=user_role,
            phone=phone,
            address=address,
            agency_name=agency_name,
            area_of_operation=area_of_operation
        )

        # Add user to session.
        db.session.add(user)

        # Commit session.
        db.session.commit()

        # Print admin user status.
        logging.info("Test agent user was set.")

        # Return user.
        return user

    else:

        # Print admin user status.
        logging.info("Agent user already set.")
