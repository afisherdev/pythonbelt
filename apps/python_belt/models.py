# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models
import bcrypt
import re

EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9\.\+_-]+@[a-zA-Z0-9\._-]+\.[a-zA-Z]*$')
NAME_REGEX = re.compile(r'^[A-Za-z]\w+$')
PASSWORD_REGEX = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[$@$!%*?&])[A-Za-z\d$@$!%*?&]{8,}$')
class User_Manager(models.Manager):
    def reg_validate(self, post_data):
        errors = []
        if not re.match(PASSWORD_REGEX, post_data['password']):
            errors.append('Password must be 8 characters, 1 uppercase and 1 lowercase letter and a number or special character')
        if post_data['password'] != post_data['confirm_pw']:
            errors.append('Passwords must match.    ')
        if len(post_data['name']) < 5:
            errors.append('Name field must be 5 characters or more.')
        if not re.match(NAME_REGEX, post_data['name']):
             errors.append('Name field must contain letters only.')
        if len(post_data['username']) <5:
            errors.append('Username must be more than 5 characters.')
        if len(post_data['name']) < 1:
            errors.append('Name field cannot be empty.')
        if post_data['email'] < 1:
            errors.append('Must Provide an Email.')
        if not re.match(EMAIL_REGEX, post_data['email']):
            errors.append('Not a Valid Email.')
        if len(post_data['username']) < 1:
            errors.append('Username Field cannot be empty')
        if not errors:
            hashed_pw = bcrypt.hashpw(post_data['password'].encode(), bcrypt.gensalt(9))
            new_user = self.create(
                name = post_data['name'],
                username = post_data['username'],
                email = post_data['email'],
                password = hashed_pw
            )
            return new_user
        return errors


    def login_validate(self, post_data):
        errors = []
        if len(self.filter(username=post_data['username'])) > 0:
            user = self.filter(username=post_data['username'])[0]
            if not bcrypt.checkpw(post_data['password'].encode(), user.password.encode()):  # <---- if not user.password and get error try using hash1.encode
                errors.append('email/password incorrect')
        
        else:
            errors.append('email/password incorrect')
        
        if errors:
            return errors
        return user

class User (models.Model):
    name = models.CharField(max_length = 255)
    username =  models.CharField(max_length = 255)
    password = models.CharField(max_length = 255)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

class Something(models.Model):
    first_name = models.CharField(max_length = 255)
    last_name = models.CharField(max_length = 255)
    # "user" = models.ForeignKey("User", related_name="something")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
     
class Something2 (models.Model):
    name = models.CharField(max_length = 255)
    username =  models.CharField(max_length = 255)
    password = models.CharField(max_length = 255)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)