# Utility numbers module

import re
from string import letters
import hashlib
import string
import random
import hmac

SECRET = 'Great!'

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASS_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")


def validate_password(password):
    return password and PASS_RE.match(password)
    
def validate_username(username):
    return username and USER_RE.match(username)

def validate_email(email):
    return not email or EMAIL_RE.match(email)

def render_str(template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

#password Hashing
def make_salt(size=5, chars=string.ascii_letters):
    return ''.join(random.choice(chars) for x in range(size))

def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s|%s' % (h, salt)

def valid_pw(name, pw, h):
    salt = h.split('|')[1]
    return h==make_pw_hash(name, pw, salt)

#Cookie stuff
def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(SECRET, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val





