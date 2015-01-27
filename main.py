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
import jinja2
import os
import main
from utils import *
import re
import time

from google.appengine.ext import db
from google.appengine.api import memcache

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

def render_str(template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

#Main Handler 
class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

    def notfound(self):
        self.error(404)
        self.write('<h1>404: Not Found</h1>Sorry, my friend, but that page does not exist.')


#Wiki Front Page Handler 


#Signup Page Handler
class Signup(Handler):
    def get(self):
        self.render('signup.html')

    def post(self):
        have_error = False

        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username=self.username, email=self.email)

        if not validate_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not validate_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not validate_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup.html', **params)
        else:
            self.done()

    def done(self):
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup.html', error_username = msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()
            self.login(u)
            self.redirect('/')

#Login Page Handler 
class Login(Handler):
    def get(self):
        self.render('login.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/')
        else:
            msg = 'Invalid Login'
            self.render('login.html', error = msg)
    

#Logout Page Handler
class Logout(Handler):
    def get(self):
        self.logout()
        self.redirect('/')



#Memcache function
def wiki_page(name, update=False):
    key = name
    wiki = memcache.get(key)
    if wiki is None or update:
        wiki = Wiki.by_name(name)
        memcache.set(key, wiki)
    return wiki

#Edit Page Handler
class EditPage(Handler):
    def get(self, wiki_name):
        if not self.user:
            self.redirect('/login')

        v = self.request.get('v')
        wiki = None
        #self.response.out.write(int(v))
        if v:
            if v.isdigit():
                wiki = Wiki.by_id(int(v))

            if not wiki:
                return self.notfound()
        else:
            wiki = Wiki.by_name(str(wiki_name[1:]))

        self.render('edit.html', name=wiki_name[1:], username=self.user.name,
                    wiki = wiki)
            


    def post(self, wiki_name):
        if not self.user:
            self.error(400)
            return
        content = self.request.get('content')
        old_page = Wiki.by_name(wiki_name[1:])
        
        if not (old_page or content):
            return
        elif not old_page or old_page.content != content:
            w = Wiki(name=wiki_name[1:], content=content)
            w.put()
            time.sleep(1)
            
        self.redirect("/%s" % str(wiki_name)[1:])
        
            
        

    
class WikiPage(Handler):
    def get(self, wiki_name):
        if self.user:
            v = self.request.get('v')
            p = None
            if v:
                if v.isdigit():
                    wiki = Wiki.by_id(int(v))
                
                if not wiki:
                    return self.notfound()
            else:
                 wiki = Wiki.by_name(str(wiki_name[1:]))

            if wiki:
                self.render('front.html', content=wiki.content,
                            wikiname=wiki.name, username=self.user.name,
                            wiki=wiki)
            else:
                self.redirect('/_edit%s' % wiki_name)
        else:
            if wiki_name[1:]:
                self.redirect('/login')
            #self.redirect('/login')
            self.render('front.html', user = self.user)
                

class HistoryPage(Handler):
    def get(self, wiki_name):
        if self.user:
            wikis = Wiki.all().filter('name =', wiki_name[1:]).order('-created')

            self.render('history.html', wikis=wikis, name=wiki_name, username = self.user.name)
        

        

#Datastore Stuff
class User(db.Model):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()
    created = db.DateTimeProperty(auto_now_add=True)

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid)

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u



class Wiki(db.Model):
    name = db.StringProperty()
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)

    @classmethod
    def by_name(cls, name):
        w = Wiki.all().filter('name =', name).order('-created').get()
        return w

    @classmethod
    def by_id(cls, wiki_id):
        return cls.get_by_id(wiki_id)
        

    def render(self):
        self._render_text = self.content.replace('/n', '<br>')
        return render_str('wiki.html', wiki=self)
    


class Test(Handler):
    def get(self):
        wiki = Wiki.by_id(int('5560230301663232'))
        self.response.write(str(wiki.content))

        


   
        
PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'
        
app = webapp2.WSGIApplication([
    ('/signup', Signup),
    ('/login', Login),
    ('/logout', Logout),
    ('/test', Test),
    ('/_edit' + PAGE_RE, EditPage),
    ('/_history' + PAGE_RE, HistoryPage),
    (PAGE_RE, WikiPage)
], debug=True)



