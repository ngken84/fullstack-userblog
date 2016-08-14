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

import os
import re
import hmac
import time
import webapp2
import jinja2
import logging
from mydbmodels import BlogPost, User, Comment, BlogPostLikes, SECRET

# jinja2 initialization
TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), 'templates')
JINJA_ENV = jinja2.Environment(autoescape=False,
                               loader=jinja2.FileSystemLoader(TEMPLATE_DIR))

#####################
# Web Page Handlers #
#####################

class Handler(webapp2.RequestHandler):
    """Handler class is the parent class for all RequestHandlers used in this
    web application. It has useful functions for writing cookies, rendering
    templates and logging users in and out.
    """

    def __init__(self, request, response):
        self.initialize(request, response)
        uid = self.read_secure_cookie('user_id')
        if uid:
            self.user = User.by_id(int(uid))
        else:
            self.user = None

    def write(self, *a, **kw):
        """Write HTTP response

        Keyword arguments:
        a -- string to write
        kw -- dictionary of arguments to write response with
        """
        self.response.out.write(*a, **kw)

    @staticmethod
    def render_str(template, **params):
        """ Return a string of a rendered Jinja2 template using passed
        parameters

        Keyword arguments:
        template -- name of the template to render
        params -- params to use to render the template
        """
        temp_t = JINJA_ENV.get_template(template)
        return temp_t.render(params)

    def render(self, template, **kw):
        """Write a HTTP response using template and parameters

        Keyword arguments:
        template -- name of template to render
        params -- params to use to render the template
        """
        self.write(self.render_str(template, **kw))

    @staticmethod
    def make_secure_val(val):
        """Return a string ready to be used as a secure cookie

        Keyword arguments:
        val -- value to make into a secure string
        """
        return '%s|%s' % (val, hmac.new(SECRET, val).hexdigest())

    def check_secure_val(self, secure_val):
        """Returns the value if the passed secured value is valid
        else returns None

        Keyword arguments:
        secure_val -- the value that needs to be validated
        """
        val = secure_val.split('|')[0]
        if secure_val == self.make_secure_val(val):
            return val

    def set_secure_cookie(self, name, val):
        """Sets a cookie that is verified with a hashed value

        Keyword arguments:
        name -- name of the cookie
        val -- value of the cookie
        """
        cookie_val = self.make_secure_val(val)
        self.response.headers.add_header('Set-Cookie',
                                         '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        """Returns the value of a secure cookie

        Keyword arguments:
        name -- name of the cookie
        """
        cookie_val = self.request.cookies.get(name)
        if cookie_val:
            return self.check_secure_val(cookie_val)

    def remove_cookie(self, name):
        """Removes a cookie of a given name

        Keyword arguments:
        name -- name of the cookie to remove
        """
        self.response.headers.add_header('Set-Cookie', '%s=; Path=/' % name)

    def login(self, user):
        """Sets a secure cookie that indicates that a user is logged in

        Keyword arguments:
        user -- the user id of the user to be logged in
        """
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        """Logs out the user by removing the 'user_id' cookie"""
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')


class MainHandler(Handler):
    """The Web Page Handler for '/' page"""

    def get(self):
        """Handles GET requests for '/' page"""
        all_posts = BlogPost.get_latest()
        myuser = self.user
        self.render("index.html",
                    user=myuser,
                    posts=all_posts)


class SignUpHandler(Handler):
    """Web page handler for '/newaccount' page
    Allows user to create new accounts
    """

    def get(self):
        """ Handles GET requests for '/newaccount' page"""
        self.render("signup.html")

    def post(self):
        """ Handles POST requests for 'newaccount' page
        Takes request parameters and registers users
        """
        # get all post parameters
        user = self.request.get('username')
        user_password = self.request.get('password')
        verify = self.request.get('verify')
        mail = self.request.get('email')
        # get all error messages
        user_error = self.get_username_error(user)
        pass_error = self.get_password1_error(user_password)
        ver_error = self.get_password2_error(user_password, verify)
        em_error = self.get_email_error(mail)
        # if error message exists, reloade the sign up page with errors
        if user_error or pass_error or ver_error or em_error:
            self.render('signup.html', username=user,
                        email=mail,
                        username_error=user_error,
                        password_error=pass_error,
                        email_error=em_error,
                        verify_error=ver_error)
            return
        # no error messages found, register user and redirect to
        # welcome page
        newuser = User.register(user, user_password, mail)
        newuser.put()
        self.set_secure_cookie('new', 'new')
        self.login(newuser)
        time.sleep(1)
        self.redirect('/welcome')

    @staticmethod
    def valid_username(username):
        """returns True if passed username is valid

        Keyword Arguments:
        username -- value that will be tested
        """
        user_re = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
        return user_re.match(username)

    def get_username_error(self, user):
        """Returns error string if username is invalid otherwise
        returns empty string

        Keyword Arguments:
        user -- value that will be tested
        """
        if user:
            # Is a user already exists with the same username?
            if User.does_user_exist(user):
                return "User with that name already exists"
            # Is the username valid
            elif not self.valid_username(user):
                return 'Please enter a valid username'
            else:
                return ''
        else:
            return "No user name entered"

    @staticmethod
    def valid_password(password):
        """Returns True if passed value is a valid password

        Keyword Arguments:
        password -- value that will be tested
        """
        pass_re = re.compile(r"^.{3,20}$")
        return pass_re.match(password)

    def get_password1_error(self, password):
        """Returns error string if password is invalid,
        otherwise returns empty string

        Keyword Arguments:
        password -- value to be tested
        """
        if password:
            if not self.valid_password(password):
                return "Please enter a valid password"
            return ''
        else:
            return "Please enter a password"

    @staticmethod
    def get_password2_error(password, verify):
        """Returns error string if password & verify password is invalid,
        otherwise returns empty string

        Keyword Arguments:
        password -- value to be tested
        verify -- value to be tested
        """
        if password and verify:
            if verify != password:
                return "Passwords do not match"
            return ''
        else:
            return "Please enter both password and confirm password fields"

    @staticmethod
    def valid_email(email):
        """Returns True if passed email is valid

        Keyword Arguments:
        email - value to be tested
        """
        email_re = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
        return email_re.match(email)

    def get_email_error(self, email):
        """Returns error string if email is invalid,
        otherwise returns empty string

        Keyword Arguments:
        email -- value to be tested
        """
        if email:
            if not self.valid_email(email):
                return "Please enter a valid email"
            ### Ensure that email is not already in use
            if User.is_email_taken(email):
                return "A user with that email account is already registered"
            return ''
        else:
            return ''


class WelcomeHandler(Handler):
    """Web page handler for '/welcome' page
    Is the page user is redirected to after creating an account
    """

    def get(self):
        """ Handles GET requests for '/welcome' page"""
        new_cookie = self.read_secure_cookie('new')
        # if doesn't have 'new' cookie or is not logged in redirect
        # to default page
        if not new_cookie or not new_cookie == 'new' or not self.user:
            self.redirect('/')
            return
        self.remove_cookie('new')
        self.render("welcome.html", user=self.user)


class SignInHandler(Handler):
    """Web page handler for '/signin' page"""

    def get(self):
        """Handles GET requests for '/signin' page"""
        self.render("signin.html")

    def post(self):
        """Handles POST request for '/signin' page
        Verify if login information entered is correct and signs in the user
        if it is
        """
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
                        username=user,
                        username_error=usr_error,
                        password_error=pss_error)
            return

        # gets user
        user_obj = User.by_name(user)

        # if user does not exists re-render page with errors
        if not user_obj:
            usr_error = 'User does not exist by that user name'
            self.render("signin.html",
                        username=user,
                        username_error=usr_error)
            return

        # check if password matches, if fails
        salt = user_obj.password.split("|")[1]
        if (not user_obj.password == User.make_pw_hash(user,
                                                       user_password,
                                                       salt)):
            self.render("signin.html",
                        username=user,
                        password_error='Invalid password')
            return

        self.login(user_obj)
        self.redirect('/')


class LogoutHandler(Handler):
    """Web page handler for '/logout' page"""

    def get(self):
        """Handles GET requests for '/logout' page
        Deletes logout cookie and redirects user to sign in page
        """
        self.logout()
        self.redirect('/signin')


class NewPostHandler(Handler):
    """Web page handler for '/blog/newpost/' url
    Page is for creating new Blog Posts
    """

    def get(self):
        """Handles GET requests for '/blog/newpost/' page"""
        myuser = self.user
        self.render('newpost.html',
                    user=myuser)

    def post(self):
        """Handles POST requests for '/blog/newpost/' page
        Determines if the new post is valid and then creates a new blog post if
        is valid.
        """
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
                        user=self.user,
                        subject=sub,
                        body_text=body,
                        subject_error=sub_error,
                        body_error=body_error)
            return

        newpost = BlogPost(subject=sub,
                           blog=body,
                           username=self.user.username,
                           like_count=0)
        newpost.put()
        BlogPost.flush_cache()
        self.redirect('/blog/%s' % newpost.key().id())


class BlogHandler(Handler):
    """Web page handler for '/blog/' url """

    def get(self):
        """Handles GET requests for '/blog/' page """
        user_id = self.request.get('user')
        my_user = self.user
        post = None
        other_user = None

        # if user_id exists, then get the user is trying to view only posts by
        # another user
        if user_id:
            other_user = User.by_name(user_id)
            if other_user:
                post = BlogPost.latest_by_name(user_id)
        # if user_id does not exist, then only get posts by the logged in user
        elif my_user:
            post = BlogPost.latest_by_name(self.user.username)

        # if not requesting another user's posts or your own posts
        # redirect to sign in page
        if not my_user and other_user is None:
            self.redirect('../signin')
            return

        self.render("blog.html",
                    user=my_user,
                    other_user=user_id,
                    posts=post)


class BlogPostHandler(Handler):
    """Web page handler for '/blog/(d+)/?' url """

    @staticmethod
    def can_user_like(user, post_id, username):
        """Returns true if a passed user is able to like a post

        Keyword Arguments:
        user -- the user that is being tested if is allowed to like a post
        post_id -- the post id for the post
        username -- the author of the post
        """
        return (not BlogPostLikes.has_user_liked(post_id, user.username) and
                not user.username == username) # pylint: disable=redefined-builtin

    def get(self, blog_id):
        """Handles GET requests for '/blog/(d+)/?' page

        Keyword Arguments:
        blog_id -- id for the blog to be rendered
        """
        post = BlogPost.by_id(int(blog_id))
        comments = Comment.get_comments_for_post(blog_id)
        if post:
            myuser = None
            can_like = False
            if self.user:
                myuser = self.user
                can_like = self.can_user_like(myuser, blog_id, post.username)
            self.render("blogpost.html",
                        user=myuser,
                        can_like=can_like,
                        blogpost=post,
                        comments=comments)
        else:
            self.redirect('../')

    def post(self, blog_id):
        """Handles POST requests for '/blog/(d+)/?' page
        This has to handle a lot of different POSTS:
        - likes
        - new comments
        - deleting posts
        - deleting comments

        Keyword Arguments:
        blog_id -- id for the blog to be rendered
        """
        post = BlogPost.by_id(int(blog_id))
        comments = Comment.get_comments_for_post(blog_id)

        # if post is not found, redirect
        if not post:
            self.redirect('../')
            return

        # if user is not logged in, display error message
        myuser = self.user
        if not myuser:
            self.render("blogpost.html",
                        user=myuser,
                        can_like=False,
                        blogpost=post,
                        errormsg="You must be logged in to perform that action",
                        comments=comments)
            return

        # if has post parameter 'like' then it is a like
        if self.request.get('like') == 'like':
            if BlogPostLikes.has_user_liked(blog_id, myuser.username):
                self.render("blogpost.html",
                            user=myuser,
                            can_like=False,
                            blogpost=post,
                            errormsg="You have already 'liked' this post",
                            comments=comments)
            elif myuser.username == post.username:
                self.render("blogpost.html",
                            user=myuser,
                            can_like=False,
                            blogpost=post,
                            errormsg="You can't like your own post",
                            comments=comments)
            else:
                new_like = BlogPostLikes(post_key_id=int(blog_id),
                                         username=myuser.username)
                new_like.put()
                post.like_count = post.like_count + 1
                post.put()
                self.render("blogpost.html",
                            user=myuser,
                            can_like=False,
                            blogpost=post,
                            comments=comments)

        # if has post parameter 'delete' then delete the post
        elif self.request.get('delete') == 'delete':
            if myuser and myuser.username == post.username:
                post.delete()
                time.sleep(1)
                BlogPost.flush_cache()
                self.redirect('/blog')
            else:
                can_like = self.can_user_like(myuser, blog_id, myuser.username)
                self.render("blogpost.html",
                            user=myuser,
                            can_like=can_like,
                            blogpost=post,
                            errormsg="You can't delete this post.",
                            comments=comments)
        # if has post parameter 'deletecomment' then delete the comment
        elif self.request.get('deletecomment') == 'delete':
            cid = self.request.get('comment')
            if myuser is None:
                self.render("blogpost.html",
                            user=myuser,
                            can_like=False,
                            blogpost=post,
                            errormsg="You must be logged "
                                     "in to delete a comment",
                            comments=comments)
                return
            elif cid:
                markedcomm = Comment.by_id(cid)
                if markedcomm and markedcomm.author == myuser.username:
                    markedcomm.delete()
                    time.sleep(1)
                    self.redirect('/blog/%s' % post.key().id())
                    return
                else:
                    can_like = self.can_user_like(myuser,
                                                  blog_id,
                                                  myuser.username)
                    self.render("blogpost.html",
                                user=myuser,
                                can_like=can_like,
                                blogpost=post,
                                errormsg="You do not have permission to "
                                         "delete this post",
                                comments=comments)
                    return
        # user is attempting to post a new comment
        else:
            can_like = self.can_user_like(myuser, blog_id, myuser.username)
            comment = self.request.get('newComment')
            if comment:
                comment_db = Comment(post_key_id=int(blog_id),
                                     author=myuser.username,
                                     comment=comment)
                comment_db.put()
                comments = [comment_db] + comments
                self.render("blogpost.html",
                            user=myuser,
                            can_like=can_like,
                            blogpost=post,
                            comments=comments)
            else:
                self.render("blogpost.html",
                            user=myuser,
                            can_like=can_like,
                            blogpost=post,
                            errormsg="You must enter a comment",
                            comments=comments)


class EditPostHandler(Handler):
    """Web page handler for '/editblog/(d+)/?' url """

    def get(self, blog_id):
        """Handles GET requests for '/editblog/(d+)/?' page

        Keyword Arguments:
        blog_id -- id for the blog to be rendered
        """
        if not self.user:
            self.redirect('../signin')
            return
        post = BlogPost.by_id(int(blog_id))
        comments = Comment.get_comments_for_post(blog_id)

        self.render("editpost.html",
                    user=self.user,
                    blogpost=post,
                    comments=comments)

    def post(self, blog_id):
        """Handles POST requests for '/editblog/(d+)/?' page

        Keyword Arguments:
        blog_id -- id for the blog to be rendered
        """
        if not self.user:
            self.redirect('../signin')
            return
        post = BlogPost.by_id(int(blog_id))
        # make sure the post author and logged in user are the same person
        if self.user.username != post.username:
            comments = Comment.get_comments_for_post(blog_id)
            self.render("editpost.html",
                        user=self.user,
                        blogpost=post,
                        comments=comments,
                        error_msg='You are not the owner of this post.')
            return
        edits = self.request.get('blog')
        if edits:
            post.blog = edits
            post.put()
            BlogPost.flush_cache()
            self.redirect('../blog/%s' % post.key().id())
        else:
            comments = Comment.get_comments_for_post(blog_id)
            self.render("editpost.html",
                        user=self.user,
                        blogpost=post,
                        comments=comments,
                        errormsg='Please enter some text.')


class EditCommentHandler(Handler):
    """Web page handler for '/editcomment/(d+)/?' url """

    def get(self, comment_id):
        """Handles GET requests for '/editcomment/(d+)/?' page

        Keyword Arguments:
        comment_id -- id for the comment to be rendered
        """
        if not self.user:
            self.redirect('../signin')
            return
        comment = Comment.by_id(comment_id)
        if not comment:
            self.redirect('../blog')
            return
        post = BlogPost.by_id(comment.post_key_id)
        if not post:
            self.redirect('../blog')
            return
        self.render("editcomment.html",
                    user=self.user,
                    blogpost=post,
                    comment=comment)

    def post(self, comment_id):
        """Handles POST requests for '/editcomment/(d+)/?' page

        Keyword Arguments:
        comment_id -- id for the comment to be rendered
        """
        if not self.user:
            self.redirect('../signin')
            return
        comment = Comment.by_id(comment_id)
        if not comment:
            self.redirect('../blog')
            return
        if comment.author != self.user.username:
            post = BlogPost.by_id(comment.post_key_id)
            self.render("editcomment.html",
                        user=self.user,
                        blogpost=post,
                        comment=comment,
                        errormsg="You can't edit another user's comment")
            return
        newcomment = self.request.get('comment')
        if not newcomment:
            post = BlogPost.by_id(comment.post_key_id)
            self.render("editcomment.html",
                        user=self.user,
                        blogpost=post,
                        comment=comment,
                        errormsg="Please enter some text")
            return
        comment.comment = newcomment
        comment.put()
        time.sleep(1)
        self.redirect('../blog/%s' % comment.post_key_id)


app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/newaccount', SignUpHandler),
    ('/welcome', WelcomeHandler),
    ('/signin', SignInHandler),
    ('/logout', LogoutHandler),
    ('/blog/newpost', NewPostHandler),
    ('/blog/?', BlogHandler),
    ('/blog/(\d+)/?', BlogPostHandler),
    ('/editpost/(\d+)/?', EditPostHandler),
    ('/editcomment/(\d+)/?', EditCommentHandler)
], debug=True)
