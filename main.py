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
        return db.GqlQuery('SELECT * FROM User WHERE __key__ = KEY(\'User\', %s)' % int(uid)).get()

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


class MainHandler(Handler):
    def get(self):
        self.render("base.html")


class SignUpHandler(Handler):
    def get(self):
        self.render("signup.html")

    def post(self):
        user = self.request.get('username')
        user_password = self.request.get('password')
        verify = self.request.get('verify')
        mail = self.request.get('email')
        self.render('signup.html', username = user,
                    email = mail)

        
        
app = webapp2.WSGIApplication([
    ('/', MainHandler), ('/newaccount', SignUpHandler)
], debug=True)
