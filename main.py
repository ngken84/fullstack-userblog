#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import webapp2
import os
import jinja2
import random
import hashlib
import string
import re

from google.appengine.ext import db

# jinja2 initialization
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir))
_external = True


#############
# DB MODELS #
#############

## User Database Model
class User(db.Model):
    username = db.StringProperty(required = True)
    password = db.StringProperty(required = True)
    email = db.StringProperty()
    created = db.DateTimeProperty(auto_now_add = True)

    @classmethod
    def by_id(cls, uid):
        return db.GqlQuery("SELECT * FROM User WHERE __key__ = KEY"
                           "(\'User\', %s)" % int(uid)).get()

    @classmethod
    def by_name(cls, name):
        return User.all().filter('name =', name).get()

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = cls.make_pw_hash(name, pw, cls.make_salt())
        return User(username = name,
                    password = pw_hash,
                    email = email)

    @classmethod
    def make_pw_hash(cls, name, pw, salt):
        return hashlib.sha256(name+pw+salt).hexdigest()+"|"+salt

    @classmethod
    def make_salt(cls):
        retval = ""
        for i in range(0,5):
            retval = retval + random.choice(string.ascii_letters)
        return retval
        

#####################
# Web Page Handlers #
#####################

## Web Page Handler Template
# Template for which all page handlers inherit from
# Includes helper functions

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

## Main Page Handler
# Handles requests for the '/' url

class MainHandler(Handler):
    def get(self):
        self.render("base.html")

## Sign Up Page Handler
# Handles requests for the '/newaccount' url

class SignUpHandler(Handler):
    def get(self):
        self.render("signup.html")

    def post(self):
        # get all post parameters
        user = self.request.get('username')
        user_password = self.request.get('password')
        verify = self.request.get('verify')
        mail = self.request.get('email')
        #get all error messages
        user_error = self.getUsernameError(user)
        pass_error = self.getPassword1Error(user_password, verify)
        ver_error = self.getPassword2Error(user_password, verify)
        em_error = self.getEmailError(mail)
        self.render('signup.html', username = user,
                    email = mail,
                    username_error = user_error,
                    password_error = pass_error,
                    email_error = em_error,
                    verify_error = ver_error)

    # returns true if a username string is valid
    def valid_username(self, username):
        user_re = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
        return user_re.match(username)

    # returns error message if passed username is invalid
    # returns empty string if passed username is valid
    def getUsernameError(self, user):
        if(user):
            users = db.GqlQuery("SELECT * FROM User WHERE "
                                " username =:1 LIMIT 1", user)
            # Is a user already exists with the same username?
            if(users.count() != 0):
                return "User with that name already exists"
            # Is the username valid
            elif(not self.valid_username(user)):
                return 'Please enter a valid username'
            else:
                return ''      
        else:
            return "No user name entered"

    # returns true if passed password is valid
    def valid_password(self, password):
        pass_re = re.compile(r"^.{3,20}$")
        return pass_re.match(password)
    
    # returns an error message string if the passed password is invalid
    # returns an empty string if the passed password is valid
    def getPassword1Error(self, password, verify):
        if(password):
            if(not self.valid_password(password)):
                return "Please enter a valid password"
            return ''
        else:
            return "Please enter a password"

    # returns an error message string if the passed password & verify
    # inputs are invalid
    # return an empty string if they are valid
    def getPassword2Error(self, password, verify):
        if(password and verify):
            if(verify != password):
                return "Passwords do not match"
            return ''
        else:
            return "Please enter both password and confirm password fields"

    # returns true if passed email address is a valid formated email
    def valid_email(self, email):
        email_re = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
        return email_re.match(email)

    # returns an error message string if the passed email address is invalid
    # returns and empty string if passed email is valid
    def getEmailError(self, email):
        if(email):
            if(not self.valid_email(email)):
                return "Please enter a valid email"
            emails = db.GqlQuery("SELECT * FROM User WHERE email =:1"
                                 "LIMIT 1", email)
            if(emails.count() != 0):
                return "A user with that email account is already registered"
            return ''
        else:
            return ''

        
app = webapp2.WSGIApplication([
    ('/', MainHandler), ('/newaccount', SignUpHandler)
], debug=True)
