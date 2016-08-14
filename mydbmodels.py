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
import time

from google.appengine.api import memcache
from google.appengine.ext import db

#############
# DB MODELS #
#############

# Hash secret value
SECRET = "aeEVC821md8D8KJid810123EMdieMDCHZPQlaelD"

class User(db.Model):
    """User represents a user of our application.

    Parameters:
    username -- the user's username. Must be unique
    password -- user's password which is stored hashed and salted
    email -- user's user name. Must be unique
    created -- created date
    """

    username = db.StringProperty(required=True)
    password = db.StringProperty(required=True)
    email = db.StringProperty()
    created = db.DateTimeProperty(auto_now_add=True)

    @classmethod
    def by_id(cls, uid):
        """Retrieves a User with passed user id

        Keyword Arguments:
        uid -- user id for desired User
        """
        return db.GqlQuery("SELECT * FROM User WHERE __key__ = KEY"
                           "(\'User\', %s)" % int(uid)).get()

    @classmethod
    def by_name(cls, name):
        """Retrieves a User with the passed username

        Keyword Arguments:
        name -- username for desired User
        """
        user = User.all().filter('username =', name).get()
        return user

    @classmethod
    def register(cls, name, passwrd, email=None):
        """Creates a User using the passed parameters and returns it

        Keyword Arguments:
        name -- the username for the user
        pw -- the password for the user
        email -- the email for the user (defaults to None)
        """
        if not email:
            email = None
        pw_hash = cls.make_pw_hash(name, passwrd, cls.make_salt())
        return User(username=name,
                    password=pw_hash,
                    email=email)

    @classmethod
    def make_pw_hash(cls, name, passwrd, salt):
        """Creates a password hash using the using a username, password and hash

        Keyword Arguments:
        name -- username
        pw -- password
        """
        return hashlib.sha256(name+passwrd+salt+SECRET).hexdigest()+"|"+salt

    @classmethod
    def make_salt(cls):
        """Generates a random 4 letter string to be used as a SALT"""
        retval = ""
        for i in range(0, 5):
            retval = retval + random.choice(string.ascii_letters)
        return retval

    @classmethod
    def does_user_exist(cls, username):
        """Checks to see if passed username is already in use

        Keyword Arguments:
        username -- username to be checked to see if exists
        """
        users = db.GqlQuery("SELECT * FROM User WHERE "
                            " username =:1 LIMIT 1", username)
        return users.count() != 0

    @classmethod
    def is_email_taken(cls, email):
        """Checks to see if passed email is already in use

        Keyword Arguments:
        email -- email to be checked to see if exists
        """
        emails = db.GqlQuery("SELECT * FROM User WHERE email =:1"
                             "LIMIT 1", email)
        return emails.count() != 0


class BlogPost(db.Model):
    """Representation of a single blog post.

    Parameters:
    subject -- subject of blog post
    blog -- text of the blog
    created -- date created
    username -- blog's author
    like_count -- number of times the blog has been liked
    """
    subject = db.StringProperty(required=True)
    blog = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    username = db.StringProperty(required=True)
    like_count = db.IntegerProperty()

    @classmethod
    def latest_by_name(cls, name):
        """Retrieves latest 10 Blog Post by passed author

        Keyword Arguments:
        name -- username of author of posts to be retrieved
        """
        posts = db.GqlQuery("SELECT * FROM BlogPost WHERE username = :1 "
                            "ORDER BY created DESC LIMIT 10", name)
        posts = list(posts)
        return posts

    @classmethod
    def get_latest(cls, update=False):
        """Retrieves latest 10 BlogPosts by all authors, unless update is True,
        will retrieve it from the cache rather than from the database

        Keyword Arguments:
        update -- if True, retrieves data from database and updates cache
        """
        posts = memcache.get('top')
        if posts is None or update:
            posts = db.GqlQuery("SELECT * FROM BlogPost "
                                " ORDER BY created DESC LIMIT 20")
            posts = list(posts)
            memcache.set('top_querytime', time.time())
            memcache.set('top', posts)
        return posts

    def formatted_date(self):
        """Returns a string formatted version of the created date"""
        return self.created.strftime('%b %d, %Y')

    @classmethod
    def flush_cache(cls):
        """Clears the BlogPost cache"""
        memcache.set('top', None)

    @classmethod
    def by_id(cls, bid):
        """Returns a BlogPost by Id

        Keyword Arguments:
        bid -- BlogPost ID for the BlogPost to be retrieved
        """
        return db.GqlQuery("SELECT * FROM BlogPost WHERE __key__ = KEY"
                           "(\'BlogPost\', %s)" % int(bid)).get()


class BlogPostLikes(db.Model):
    """Keeps track of User's likes and which posts they have liked

    Parameters:
    post_key_id -- Key Id for Blog Post
    username -- username of the User who liked
    """
    post_key_id = db.IntegerProperty()
    username = db.StringProperty(required=True)

    @classmethod
    def has_user_liked(cls, post_id, user):
        """Returns true if user has liked the BlogPost with the passed
        BlogPost key id passed

        Keyword Arguments:
        post_id -- BlogPost key id
        user -- username for user who the query is about
        """
        likes = db.GqlQuery("SELECT * FROM BlogPostLikes "
                            " WHERE post_key_id = :key AND "
                            " username = :user ", key=post_id, user=user)
        likes = list(likes)
        return len(likes) > 0


class Comment(db.Model):
    """A comment on a BlogPost

    Parameters:
    post_key_id -- key id for the BlogPost that the comment refers to
    author -- author of the Comment
    comment -- text of the Comment
    created -- creation date of the Comment
    """
    post_key_id = db.IntegerProperty()
    author = db.StringProperty(required=True)
    comment = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)

    @classmethod
    def get_comments_for_post(cls, post_id):
        """Retrieves all Comments for a BlogPost

        Keyword Arguments:
        post_id -- key id for the BlogPost
        """
        comm = db.GqlQuery("SELECT * FROM Comment "
                           "WHERE post_key_id = %s "
                           "ORDER BY created DESC " % post_id)
        comm = list(comm)
        return comm

    @classmethod
    def by_id(cls, cid):
        """Retrieves Comment by its key id

        Keyword Arguments:
        cid -- key id for the Comment
        """
        return db.GqlQuery("SELECT * FROM Comment WHERE __key__ = KEY"
                           "(\'Comment\', %s)" % int(cid)).get()

    def formatted_date(self):
        """Returns the created date as a formatted String"""
        return self.created.strftime('%b %d, %Y')
