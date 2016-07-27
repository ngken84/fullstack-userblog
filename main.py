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
import string
import re
import hmac
import time
import logging
from mydbmodels import *

# jinja2 initialization
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(autoescape=False, loader = jinja2.FileSystemLoader(template_dir))
_external = True


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

    def make_secure_val(self, val):
        return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

    def check_secure_val(self, secure_val):
        val = secure_val.split('|')[0]
        if(secure_val == self.make_secure_val(val)):
            return val

    def set_secure_cookie(self, name, val):
        cookie_val = self.make_secure_val(val)
        self.response.headers.add_header('Set-Cookie',
                                         '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        if(cookie_val):
            return self.check_secure_val(cookie_val)

    def remove_cookie(self, name):
        self.response.headers.add_header('Set-Cookie', '%s=; Path=/' % name)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        logging.info('MyHandlerTemplate::initialize')
        uid = self.read_secure_cookie('user_id')
        logging.info(uid)
        if uid:
            self.user = User.by_id(int(uid))
        else:
            self.user = None
            

## Main Page Handler
# Handles requests for the '/' url

class MainHandler(Handler):
    def get(self):
        all_posts = BlogPost.get_latest()
        if self.user:
            self.render("index.html",
                        user = self.user,
                        posts = all_posts)
        else:
            self.render("index.html",
                        posts = all_posts)
        

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
        # get all error messages
        user_error = self.getUsernameError(user)
        pass_error = self.getPassword1Error(user_password, verify)
        ver_error = self.getPassword2Error(user_password, verify)
        em_error = self.getEmailError(mail)
        # if error message exists, reloade the sign up page with errors
        if user_error or pass_error or ver_error or em_error:
            self.render('signup.html', username = user,
                        email = mail,
                        username_error = user_error,
                        password_error = pass_error,
                        email_error = em_error,
                        verify_error = ver_error)
            return
        # no error messages found, register user and redirect to
        # welcome page
        u = User.register(user, user_password, mail)
        u.put()
        self.set_secure_cookie('new','new')
        self.login(u)
        time.sleep(1)
        self.redirect('/welcome')
        

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


## Welcome Page Handler
# Handles requests for the '/welcome' url

class WelcomeHandler(Handler):
    def get(self):
        new_cookie = self.read_secure_cookie('new')
        # if doesn't have 'new' cookie or is not logged in redirect
        # to default page
        if(not new_cookie or not new_cookie == 'new' or not self.user):
            self.redirect('/')
            return
        self.remove_cookie('new')
        self.render("welcome.html", user = self.user)

## Sign In Page Handler
# Handles requests for the '/signin' url

class SignInHandler(Handler):
    def get(self):
        self.render("signin.html")

    def post(self):
        # get post parameters
        user = self.request.get('username')
        user_password = self.request.get('password')

        #determine errors
        usr_error = ''
        pss_error = ''

        if not user:
            usr_error = 'Please enter your user name'

        if not user_password:
            pss_error = 'Please enter your password'

        # if errors exists re-render pages with errors
        if usr_error or pss_error:
            self.render("signin.html",
                        username = user,
                        username_error = usr_error,
                        password_error = pss_error)
            return

        # gets user
        user_obj = User.by_name(user)

        # if user does not exists re-render page with errors
        if not user_obj:
            usr_error = 'User does not exist by that user name'
            self.render("signin.html",
                        username = user,
                        username_error = usr_error)
            return

        # check if password matches, if fails 
        salt = user_obj.password.split("|")[1]
        if not user_obj.password == User.make_pw_hash(user, user_password, salt):
            self.render("signin.html",
                        username = user,
                        password_error = 'Invalid password')
            return

        
        self.login(user_obj)
        self.redirect('/')
           
        
## Logout Page Handler
# Handles requests for the '/logout' url

class LogoutHandler(Handler):
    def get(self):
        self.response.delete_cookie('user_id')
        self.redirect('/signin')


## New Blog Page Handler
# Handles requests for the '/blog/newpost' url

class NewPostHandler(Handler):
    def get(self):
        if(not self.user):
            self.redirect('../signin')
            return
        self.render('newpost.html',
                    user = self.user)

    def post(self):
        if not self.user:
            self.redirect('../signin')
            return

        # get post parameters
        sub = self.request.get('subject')
        body = self.request.get('blog-text')

        sub_error = ''
        body_error = ''

        # set error is subject is empty
        if not sub:
            sub_error = 'Please enter a subject'

        # set error if body is empty
        if not body:
            body_error = 'Please enter some text'

        # if error message is set, render page with errors
        if body_error or sub_error:
            self.render('newpost.html',
                        user = self.user,
                        subject = sub,
                        body_text = body,
                        subject_error = sub_error,
                        body_error = body_error)
            return

        b = BlogPost(subject = sub,
                     blog = body,
                     username = self.user.username,
                     like_count = 0)
        b.put()
        memcache.set('top', None)
        self.redirect('/blog/%s' % b.key().id())
        
## New Blog Page Handler
# Handles requests for the '/blog/newpost' url

class BlogHandler(Handler):
    def get(self):
        if(not self.user):
            self.redirect('../signin')
            return
        p = BlogPost.latest_by_name(self.user.username)
        self.render("blog.html",
                    user = self.user,
                    posts = p)


## New Blog Page Handler
# Handles requests for the '/blog/(\d+)/?' url

class BlogPostHandler(Handler):

    def can_user_like(cls, user, post_id, username):
        return not BlogPostLikes.has_user_liked(post_id, username) and not user.username == username
    
    def get(self, blog_id):
        p = BlogPost.get_by_id(int(blog_id))
        comments = Comment.get_comments_for_post(blog_id)
        if p:
            myuser = None
            can_like = False
            if self.user:
                myuser = self.user
                can_like = self.can_user_like(myuser, blog_id, myuser.username)
            self.render("blogpost.html",
                        user = myuser,
                        can_like = can_like,
                        blogpost = p,
                        comments = comments)
        else:
            self.redirect('../')

    def post(self, blog_id):
        p = BlogPost.get_by_id(int(blog_id))
        comments = Comment.get_comments_for_post(blog_id)

        # if post is not found, redirect
        if not p:
            self.redirect('../')
            return

        # if user is not logged in, display error message
        myuser = self.user
        if not myuser:
            self.render("blogpost.html",
                        user = myuser,
                        can_like = False,
                        blogpost = p,
                        errormsg = "You must be logged in to perform that action",
                        comments = comments)
            return

        # if has post parameter 'like' then it is a like
        if self.request.get('like') == 'like':
            if BlogPostLikes.has_user_liked(blog_id, myuser.username):
                self.render("blogpost.html",
                            user = myuser,
                            can_like = False,
                            blogpost = p,
                            errormsg = "You have already 'liked' this post",
                            comments = comments)
            elif myuser.username == p.username:
                self.render("blogpost.html",
                            user = myuser,
                            can_like = False,
                            blogpost = p,
                            errormsg = "You can't like your own post",
                            comments = comments)
            else:
                new_like = BlogPostLikes(post_key_id = int(blog_id),
                                         username = myuser.username)
                new_like.put()
                p.like_count = p.like_count + 1
                p.put()
                self.render("blogpost.html",
                        user = myuser,
                        can_like = False,
                        blogpost = p,
                        comments = comments)
        # user is attempting to post a new comment
        else:
            can_like = self.can_user_like(myuser, blog_id, myuser.username)
            comment = self.request.get('newComment')
            if(comment):
                comment_db = Comment(post_key_id = int(blog_id),
                                     author = myuser.username,
                                     comment = comment)
                comment_db.put()
                comments = [comment_db] + comments
                self.render("blogpost.html",
                            user = myuser,
                            can_like = can_like,
                            blogpost = p,
                            comments = comments)
            else:
                self.render("blogpost.html",
                            user = myuser,
                            can_like = can_like,
                            blogpost = p,
                            errormsg = "You must enter a comment",
                            comments = comments)
        

        
            
                        

app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/newaccount', SignUpHandler),
    ('/welcome', WelcomeHandler),
    ('/signin', SignInHandler),
    ('/logout', LogoutHandler),
    ('/blog/newpost', NewPostHandler),
    ('/blog/?', BlogHandler),
    ('/blog/(\d+)/?', BlogPostHandler)
], debug=True)
