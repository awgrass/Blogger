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
import webapp2
import codecs
import jinja2
import hashlib
import hmac
import random
import string
import json
from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)

SECRET = "dontspellme"

months = ['January',
          'February',
          'March',
          'April',
          'May',
          'June',
          'July',
          'August',
          'September',
          'October',
          'November',
          'December']

dictionary = {'a':'n', 'b':'o', 'c':'p',
             'd':'q', 'e':'r', 'f':'s',
             'g':'t','h':'u','i':'v',
             'j':'w', 'k':'x','l':'y',
             'm':'z','n':'a','o':'b',
             'p':'c','q':'d','r':'e',
             's':'f','t':'g','u':'h',
             'v':'i', 'w':'j','x':'k',
             'y':'l','z':'m'}


def escape_html(s):
    for (left, right) in (("&", "&amp;"),
                (">", "&gt;"),
                ("<", "&lt;"),
                ('"', "&quot;")):
        s = s.replace(left, right)
    return s


def valid_month(month):
    if month:
        cap_month = month.capitalize()
        if cap_month in months:
            return cap_month

def valid_day(day):
    if day.isdigit() and 1 <= int(day) <= 31:
        return int(day)

def valid_year(year):
    if year.isdigit():
        year = int(year)
        if 2020 > year > 1900:
            return year
    else:
        return None

def rot_13(string):
  return string.encode('rot13')

def valid_username(username):
	regObj = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
	return regObj.match(username)

def valid_password(password):
	regObj = re.compile(r"^.{3,20}$")
	return regObj.match(password)

def valid_email(email):
	regObj = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
	return regObj.match(email)

def render_str(template, **params):
  t = jinja_env.get_template(template)
  return t.render(params)

def hash_str(s):
  x = hmac.new(SECRET,s).hexdigest()
  return x

def make_secure_val(s):
  hashed_string = hash_str(s)
  return s + "|" + hashed_string

def check_secure_val(h):
  list = h.split("|")
  if(hash_str(list[0]) == list[1]):
    return list[0]

def make_salt():
  return ''.join(random.choice(string.ascii_letters) for letter in range(5))

def make_pw_hash(name, pw):
  salt = make_salt()
  x = hashlib.sha256(name + pw + salt).hexdigest()
  return x + "," + salt

def valid_pw(name, pw, h):
  hash_value = h.split(",")[0]
  salt = h.split(",")[1]
  new_h = hashlib.sha256(name + pw + salt).hexdigest()
  if(new_h == hash_value):
    return True







class Handler(webapp2.RequestHandler):
  def write(self, *a, **kw):
    self.response.out.write(*a, **kw)

  def render_str(self, template, **params):
    return render_str(template, **params)

  def render(self, template, **kw):
    self.write(self.render_str(template, **kw))

class User(db.Model):
  username = db.StringProperty(required = True)
  password_hash = db.StringProperty(required = True)
  email = db.EmailProperty(required = True)

class SignupHandler(Handler):

  def get(self):
      self.render("signup.html", error="", username=self.request.get('username'), password="", verify="", email=self.request.get('email'))

  def post(self):
      user_name = self.request.get('username')
      user_password = self.request.get('password')
      user_verify = self.request.get('verify')
      user_email = self.request.get('email')

      username = valid_username(user_name)
      password = valid_password(user_password)
      verify = valid_password(user_verify)
      email = valid_email(user_email)

      verify_check = (user_password == user_verify)

      if not(username and password and verify and email and verify_check):
        self.render("signup.html", error="Sorry, you provided wrong or insufficient data! Try again!",
                username=user_name, password="", verify="", email=user_email)
      else:
        user = db.GqlQuery("SELECT * from User WHERE username= :user", user=user_name).get()
        if user:
            self.render("signup.html", error="User already exists!", username=user_name, password="", verify="", email=user_email)

        else:
          new_user = User(username = user_name, password_hash = make_pw_hash(user_name, user_password), email = user_email)
          new_user.put()
          user_id = str(new_user.key().id())
          cookie_val = make_secure_val(user_id)

          self.response.headers.add_header('Set-Cookie', 'user_id=%s; Path=/' % cookie_val)
          #self.response.set_cookie('user_id', cookie_val)

          self.redirect("/blog")

class LoginHandler(Handler):
  def get(self):
    self.render("login.html", username = self.request.get("username"))
  def post(self):
    user_name = self.request.get("username")
    password = self.request.get("password")

    user = db.GqlQuery("Select * from User where username= :user", user=user_name).get()
    if(user):
      valid_user = valid_pw(user_name, password, user.password_hash)

    if(user and valid_user):
      user_id = str(user.key().id())
      cookie_val = make_secure_val(user_id)
      self.response.headers.add_header('Set-Cookie', 'user_id=%s; Path=/' % cookie_val)
      #self.response.set_cookie('user_id', cookie_val)
      self.redirect("/blog")
    else:
      self.render("login.html", error="Wrong Userdata!")

class LogoutHandler(Handler):
  def get(self):
    self.response.delete_cookie('user_id')
    self.redirect("/blog/signup")

class Post(db.Model):
  subject = db.StringProperty(required = True)
  content = db.TextProperty(required = True)
  created = db.DateTimeProperty(auto_now_add = True)

  def render(self):
    self._render_text = self.content.replace('\n', '<br>')
    return render_str("post.html", p = self)


class NewpostHandler(Handler):
  def get(self):
    user_cookie_str = self.request.cookies.get('user_id')

    if(user_cookie_str and (check_secure_val(user_cookie_str))):
      self.render("newpost.html")
    else:
      self.response.delete_cookie('user_id')
      self.redirect("/blog/signup")

  def post(self):

    user_subject = self.request.get('subject')
    user_content = self.request.get('content')

    if not (user_subject and user_content):
      self.render("newpost.html", error="Please provide at least a titel and some content!", subject = user_subject, content = user_content)
    else:
      user_cookie_str = self.request.cookies.get('user_id')

      if(user_cookie_str and (check_secure_val(user_cookie_str))):
        new_db_entry = Post(subject = user_subject, content = user_content)
        new_db_entry.put()
        link = str(new_db_entry.key().id())
        self.redirect("/blog/%s" %link)

      else:
        self.response.delete_cookie('user_id')
        self.redirect("/blog/signup")


class BlogHandler(Handler):
  def get(self):
    user_cookie_str = self.request.cookies.get('user_id')

    if(user_cookie_str and (check_secure_val(user_cookie_str))):
      self.response.headers['Content-Type'] = 'text/html'
      user_id = int(user_cookie_str.split("|")[0])
      username = User.get_by_id(user_id).username
      entries = db.GqlQuery("SELECT * FROM Post ORDER BY created DESC limit 10")
      self.render("blog.html", db_entries = entries, username=username)
    else:
      self.response.delete_cookie('user_id')
      self.redirect("/blog/signup")


class WelcomeHandler(Handler):
  def get(self):
    user_cookie_str = self.request.cookies.get('user_id')

    if(user_cookie_str and (check_secure_val(user_cookie_str))):
      user_id = int(user_cookie_str.split("|")[0])
      username= User.get_by_id(user_id).username
      self.render("welcome.html", username=username)

    else:
      self.response.delete_cookie('user_id')
      self.redirect("/signup")

class PermalinkHandler(Handler):
  def get(self, post_id):
    user_cookie_str = self.request.cookies.get('user_id')

    if(user_cookie_str and (check_secure_val(user_cookie_str))):
      entry = Post.get_by_id(int(post_id))
      self.render("permalink.html", db_entry = entry)
    else:
      self.response.delete_cookie('user_id')
      self.redirect("/blog/signup")

class JsonBlogHandler(Handler):
  def get(self):
    self.response.headers['Content-Type'] = 'application/json'
    entries = db.GqlQuery("SELECT * FROM Post ORDER BY created DESC").fetch(limit = 10)
    mylist = []

    for entry in entries:
      d = {"subject": entry.subject,
           "content": entry.content,
           "created": entry.created.strftime("%c")}

      mylist.append(d)

      text = json.dumps(mylist)
    self.write(text)

class JsonPostHandler(Handler):
  def get(self, post_id):
    self.response.headers['Content-Type'] = 'application/json'
    entry = Post.get_by_id(int(post_id))
    if entry:
      d = {"subject": entry.subject,
           "content": entry.content,
           "created": entry.created.strftime("%c")}
      self.write(json.dumps(d))
    else:
      self.response.headers['Content-Type'] = 'text/html'
      self.write("Post doesn't exist !")




app = webapp2.WSGIApplication([
    ('/', SignupHandler),('/signup', SignupHandler), ('/blog/signup', SignupHandler),
    ('/blog/welcome', WelcomeHandler), ('/blog/newpost', NewpostHandler), ('/blog', BlogHandler),
    ('/blog/([0-9]+)', PermalinkHandler), ('/blog/login', LoginHandler), ('/blog/logout', LogoutHandler),
    ('/blog.json', JsonBlogHandler), ('/blog/([0-9]+).json', JsonPostHandler) ], debug=True)
