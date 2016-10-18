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
import random
import hashlib
import hmac
import logging
import json
import string
from datetime import datetime,timedelta
from string import letters

import webapp2
import jinja2
SECRET = 'imsosecret'
from google.appengine.ext import db
from google.appengine.api import memcache

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)



# template_dir=os.path.join(os.path.dirname("_file_"),'templates')
# jinja_env=jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),autoescape=True)

cookie_seperator='|'

def hash_str(s):
	return hmac.new(SECRET,s).hexdigest()


def make_secure_val(s):
	return "%s%s%s"%(s,cookie_seperator,hash_str(s))

def check_secure_val(h):
	val=h.split(cookie_seperator)[0]
	if h==make_secure_val(val):
		return val




def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

class Handler(webapp2.RequestHandler):
	def write(self,*a,**kw):
		self.response.out.write(*a,**kw)

	def	render_str(self,template,**params):
		t=jinja_env.get_template(template)
		return t.render(params)

	def render(self,template,**kw):
		self.write(self.render_str(template,**kw))

	def render_json(self, d):
	   json_txt = json.dumps(d)
	   self.response.headers['Content-Type'] = 'application/json; charset=UTF-8'
	   self.write(json_txt)		

	def set_secure_cookie(self,name,val):
		cookie_val=make_secure_val(val)
		self.response.headers.add_header('Set-Cookie', '%s=%s; Path=/' % (name,cookie_val))

	def read_secure_cookie(self,name):
		cookie_val=self.request.cookies.get(name)
		return cookie_val and check_secure_val(cookie_val)

	def login(self,user):
		self.set_secure_cookie('user-id',str(user.key().id()))

	def logout(self):
		self.response.headers.add_header('Set-Cookie', 'user-id=; Path=/')

	def initialize(self,*a,**kw):
		webapp2.RequestHandler.initialize(self,*a,**kw)
		uid=self.read_secure_cookie('user-id')
		self.user=uid and User.by_id(int(uid))

		if self.request.url.endswith('.json'):
		    self.format = 'json'
		else:
		    self.format = 'html'
		

	


def make_salt(length=5):
    return ''.join(random.choice(string.letters) for x in xrange(length))



def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s|%s' % (salt, h)

def valid_pw(name, pw, h):
    salt=h.split(cookie_seperator)[0]
    return h==make_pw_hash(name,pw,salt)	


def users_key(group='default'):
	return db.Key.from_path('users',group)    

def blog_key(name='default'):
	return db.Key.from_path('blogs',name)


class Post(db.Model):
	subject = db.StringProperty(required = True)
	content = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)
	last_modified = db.DateTimeProperty(auto_now = True)

	def render(self):
	    self._render_text = self.content.replace('\n', '<br>')
	    return render_str("post.html", p = self)

	def as_dict(self):
	    time_fmt = '%c'
	    d = {'subject': self.subject,
	         'content': self.content,
	         'created': self.created.strftime(time_fmt),
	         'last_modified': self.last_modified.strftime(time_fmt)}
	    return d
	

def age_set(key,val):
	save_time=datetime.utcnow()
	memcache.set(key,(val,save_time))


def age_get(key):
	r=memcache.get(key)
	if r:
		val, save_time=r
		age=(datetime.utcnow()-save_time).total_seconds()
	else:
		val,age=None,0

	return val,age



def get_posts(update=False):
	key='post'
	posts,age=age_get(key)
	if posts is None or update:
		logging.error("DB QUERY")
		posts = Post.all().order('-created').fetch(limit=10)
		posts=list(posts)
		age_set(key,posts)
	return posts,age

def age_str(age):
	s='queried %s seconds ago'
	age=int(age)
	if(age==1):
		s=s.replace('seconds','second')
	return s%age	




class BlogFront(Handler):
		 
	def get(self):
        
		posts,age = get_posts()
		
		if self.format == 'html':
		    self.render('front-page.html', posts = posts,age=age_str(age),s=self)
		else:
		    return self.render_json([p.as_dict() for p in posts])

class PostPage(Handler):
	def get(self,post_id):
		post_key='POST_'+post_id
		post,age=age_get(post_key)
		if not post:
			key=db.Key.from_path('Post',int(post_id),parent=blog_key())
			post=db.get(key)
			age_set(post_key,post)
			age=0

		if not post:
		    self.error(404)
		    return
		if self.format == 'html':
		    self.render("permalink.html", post = post,age=age_str(age),s=self)
		else:
		    self.render_json(post.as_dict())





				
				    


class NewPostHandler(Handler):
	def render_newpost(self,subject="",content="",error=""):
		self.render("newpost.html",subject=subject,content=content,error=error,s=self)

	def get(self):
		if self.user:
			self.render_newpost()
		else:
			self.redirect('/login')
				

	def post(self):
		subject=self.request.get("subject")
		content=self.request.get("content")

		if subject and content:
		    p = Post(parent = blog_key(), subject = subject, content = content)
		    p.put()
		    get_posts(True)
		    memcache.flush_all()
		    self.redirect('/blog/%s' % str(p.key().id()))
		else:
		    error = "subject and content, please!"
		    self.render("newpost.html", subject=subject, content=content, error=error,s=self)






USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

class User(db.Model):
	name=db.StringProperty(required=True)
	pw_hash=db.StringProperty(required=True)
	email=db.StringProperty()

	@classmethod
	def by_id(cls,uid):
		return User.get_by_id(uid,parent=users_key())

	@classmethod
	def by_name(cls,name):
		u =User.all().filter('name =', name).get()
		return u


	@classmethod
	def register(cls,name,pw,email=None):
		pw_hash=make_pw_hash(name,pw)
		return User(parent=users_key(),name=name,pw_hash=pw_hash,email=email)

	@classmethod
	def login(cls,name,pw):
		u=cls.by_name(name)
		if u and valid_pw(name,pw,u.pw_hash):
			return u


		



class MainPage(Handler):
  def get(self):
      if self.user:
      	self.redirect('/blog')
      else:
      	self.redirect('/login')




class Signup(Handler):
	
    def get(self):
        self.render("Signup-newpage.html",s=self)

    def write_form(self,username_error="",password_error="",verify_error="",email_error="",username="",email=""):
    	  self.render("Signup-newpage.html",error_username=username_error,error_password=password_error,error_verify=verify_error,error_email=email_error,Username=username,Email=email,s=self)
	    

    def post(self):
    	have_Error=False
    	username_error=""
    	password_error=""
        verify_error=""
        email_error=""

    	self.username=self.request.get("Username")
    	self.password=self.request.get("Password")
    	self.verify=self.request.get("Verify")
    	self.email=self.request.get("Email")

    	if not valid_username(self.username):
    		username_error="That was an invalid username"
    		have_Error=True

    	if not valid_password(self.password):
    		password_error="That was an invalid password"
    		have_Error=True
    	elif self.password!=self.verify:
    		verify_error="Your passwords did not match"
    		have_Error=True

    	if not valid_email(self.email):
    		email_error="That was an invalid email"
    		have_Error=True
        
        if have_Error:
        	self.write_form(username_error,password_error,verify_error,email_error,self.username,self.email)
        else:
        	self.done()

    def done(self,*a,**kw):
    	raise NotImplementedError


class Unit2Signup(Signup):

	def done(self):
		self.redirect("/unit2/welcome?username="+self.username)


class Register(Signup):
	def done(self):
	    #make sure the user doesn't already exist
	    u = User.by_name(self.username)
	    if u:
	        msg = 'That user already exists.'
	        self.render('Signup-newpage.html', error_username = msg,s=self)
	    else:
	        u = User.register(self.username, self.password, self.email)
	        u.put()

	        self.login(u)
	        self.redirect('/blog')

class Login(Handler):
	def get(self):
		if self.user:
			self.redirect('/blog')
		else:	
			self.render('Login.html',s=self)

	def post(self):
		username=self.request.get('username')
		password=self.request.get('password')

		
		u = User.login(username, password)
		if u:
		    self.login(u)
		    self.redirect('/blog')
		    
		else:
		    msg = 'Incorrect username or password'
		    self.render('Login.html', error = msg,username=username,s=self)


class Logout(Handler):
	def get(self):
		self.logout()
		self.redirect('/login')







			


class Unit3Welcome(Handler):
	def get(self):
		if self.user:
			self.render('welcome.html',username=self.user.name)
		else:
			self.redirect('/logout')
			

	


class Welcome(Handler):
   		def get(self):
   			username=self.request.get("username") 
   			if valid_username(username):
   				self.render("welcome.html",username=username)
   			else:
   				self.redirect("/")

class FlushHandler(Handler):
	def get(self):
		memcache.flush_all()
		self.redirect('/blog')




app = webapp2.WSGIApplication([('/', MainPage),
                               ('/unit2/signup', Unit2Signup),
                               ('/unit2/welcome', Welcome),
                               ('/blog/?(?:.json)?', BlogFront),
                               ('/blog/([0-9]+)(?:.json)?', PostPage),
                               ('/newpost', NewPostHandler),
                               ('/blog/flush',FlushHandler),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/unit3/welcome', Unit3Welcome),

                               ],
                              debug=True)
