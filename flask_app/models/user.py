
from flask_app.config.mysqlconnection import connectToMySQL
from flask import flash
import re
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')


class User:
    def __init__(self, data):
        self.id = data['id']
        self.first_name = data['first_name']
        self.last_name = data['last_name']
        self.email = data['email']
        self.password = data['password']
        self.created_at = data['created_at']
        self.updated_at = data['updated_at']

    @classmethod
    def create_user(cls, data):
        query = "INSERT INTO users (first_name, last_name, email,password) VALUES (%(first_name)s, %(last_name)s, %(email)s,%(password)s);"
        result = connectToMySQL('login_schema').query_db(query, data)
        return result

    @staticmethod
    def validate_register(data):
        is_valid = True
        if len(data['first_name']) == 0:
            flash("first name must be at least 2 characters.")
            is_valid = False
        if len(data['last_name']) == 0:
            flash(" last_name must be at least 2 characters.")
            is_valid = False
        if len(data['email']) == 0:
            flash("email is required.")
            is_valid = False
        elif not EMAIL_REGEX.match(data['email']):
            flash("Invalid email address!")
            is_valid = False
        if len(data['password']) < 4:
            flash("password must be at least 4 characters.")
            is_valid = False
        elif data['password'] != data['confirm_password']:
            flash("password don't match")
            is_valid = False

        email_data = {"email": data["email"]}
        existing_user = User.get_user_email(email_data)
        if existing_user:
            flash("this email is already registered")
            is_valid = False
        return is_valid

    @classmethod
    def get_user_email(cls, data):
        query = "select * from users  where (email)  = (%(email)s);"
        result = connectToMySQL('login_schema').query_db(query, data)
        if len(result) == 0:
            return False
        return User(result[0])

    @classmethod
    def get_user_id(cls, data):
        query = "select * from users  where (id)  = (%(id)s);"
        result = connectToMySQL('login_schema').query_db(query, data)
        if len(result) == 0:
            return False
        return User(result[0])

    @staticmethod
    def validate_login(data):
        is_valid = True
        if len(data['email']) == 0:
            flash("email is required.")
            is_valid = False
        if len(data['password']) == 0:
            flash(" password is required.")
            is_valid = False
        return is_valid
