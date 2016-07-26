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
import random
import hashlib
import string
import re
import hmac
import time
import logging

from google.appengine.api import memcache
from google.appengine.ext import db

# Hash secret value
secret = "aeEVC821md8D8KJid810123EMdieMDCHZPQlaelD"

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
        u = User.all().filter('username =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        if(not email):
            email = None
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


## User Blog Post Model
class BlogPost(db.Model):
    subject = db.StringProperty(required = True)
    blog = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    username = db.StringProperty(required = True)
    like_count = db.IntegerProperty()

    @classmethod
    def latest_by_name(cls, name):
        posts = db.GqlQuery("SELECT * FROM BlogPost WHERE username = '%s' "
                            "ORDER BY created DESC LIMIT 10" % name)
        posts = list(posts)
        return posts

    @classmethod
    def get_latest(cls, update = False):
        posts = memcache.get('top')
        if posts is None or update:
            posts = db.GqlQuery("SELECT * FROM BlogPost "
                                " ORDER BY created DESC LIMIT 10")
            posts = list(posts)
            memcache.set('top_querytime', time.time())
            memcache.set('top', posts)
        return posts

## Blog Post Likes Model
class BlogPostLikes(db.Model):
    post_key_id = db.IntegerProperty()
    username = db.StringProperty(required = True)

    @classmethod
    def has_user_liked_post(cls, post_id, user):
        likes = db.GqlQuery("SELECT * FROM BlogPostLikes "
                            " WHERE post_key_id = %s AND "
                            " username = '%s' " % (post_id, user))
        likes = list(likes)
        return len(likes) > 0
        
        
