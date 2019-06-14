#Adapted from: https://github.com/auth0-samples/auth0-python-web-app/blob/master/01-Login/server.py
#by combining with
#https://github.com/auth0-samples/auth0-python-api-samples/blob/master/00-Starter-Seed/server.py

#Mostly inspired by:
#https://github.com/Stroomversnelling/monitoring_udb_resource_server/blob/master/authorization_client.py

#Another interesting example (whose idea hasn't been accommodated)
#https://github.com/david4096/flask-auth0-example/blob/master/app.py


#groups, roles and permissions have been added via Authorization extension.
#https://auth0.com/docs/extensions/authorization-extension/v2/api-access
#https://auth0.com/docs/extensions/authorization-extension/v2/implementation/configuration
#https://auth0.com/docs/extensions/authorization-extension/v2/rules
#I can now craft a payload like:
#{'sub': 'auth0|5d02ff42d62afc0c9f9e845f', 'nickname': 'sung.bae', 'name': 'sung.bae@canterbury.ac.nz', 'picture': 'https://s.gravatar.com/avatar/c92f134b284130a6369ca5a41c85cb26?s=480&r=pg&d=https%3A%2F%2Fcdn.auth0.com%2Favatars%2Fsu.png', 'updated_at': '2019-06-14T02:09:10.319Z', 'http://seistech.nz/claims/permissions': ['read:eaonly', 'read:devonly'], 'http://seistech.nz/claims/groups': ['dev', 'ea'], 'http://seistech.nz/claims/roles': ['devRole', 'eaRole']}
#Note that I have created groups and roles, and permissions for a role. Groups can do nested groups such as dev < ea < (all users) and 
# assigning a role to a group is adequate to assign permissions to group. ie. devRole is assigned to dev group, eaRole is assigned to ea group
# then a dev member is automatically authorized to both devRole and eaRole.

#Scopes associated with permission are added to the original scope by: 
#rules given in https://auth0.com/docs/architecture-scenarios/spa-api/part-2

"""Python Flask WebApp Auth0 integration example
"""
from functools import wraps
import json
from os import environ as env
from werkzeug.exceptions import HTTPException
from werkzeug.exceptions import Unauthorized

from dotenv import load_dotenv, find_dotenv
from flask import Flask
from flask import jsonify
from flask import redirect
from flask import render_template
from flask import session
from flask import url_for
from flask import request
from flask import _request_ctx_stack
from flask_cors import cross_origin
from flask_session import Session
from authlib.flask.client import OAuth
from six.moves.urllib.parse import urlencode
from six.moves.urllib.request import urlopen
from urllib.parse import urlencode

import sys

from jose import JWTError, jwt
import six

import constants

JWT_ALGORITHM = "RS256"

ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)

AUTH0_CALLBACK_URL = env.get(constants.AUTH0_CALLBACK_URL)
AUTH0_CLIENT_ID = env.get(constants.AUTH0_CLIENT_ID)
AUTH0_CLIENT_SECRET = env.get(constants.AUTH0_CLIENT_SECRET)
AUTH0_DOMAIN = env.get(constants.AUTH0_DOMAIN)
AUTH0_BASE_URL = 'https://' + AUTH0_DOMAIN
AUTH0_AUDIENCE = env.get(constants.AUTH0_AUDIENCE)
#if AUTH0_AUDIENCE is '':
#    AUTH0_AUDIENCE = AUTH0_BASE_URL + '/userinfo'
#AUTH0_AUDIENCE="http://localhost:3000/api" #Not sure if we need both audiences..
#AUTH0_AUDIENCE="organize"
#AUTH0_AUDIENCE="urn:auth0-authz-api"
SCOPE = 'openid profile groups roles permissions read:eaonly read:devonly' #only openid profile work
JWT_PAYLOAD = 'jwt_payload'
TOKEN_KEY = 'auth0_token'

ISSUER = "https://"+AUTH0_DOMAIN+"/"
#Needs API setup  https://auth0.com/docs/quickstart/backend/python#validate-access-tokens


JWT_VERIFY_DEFAULTS = {
    'verify_signature': True,
    'verify_aud': True,
    'verify_iat': True,
    'verify_exp': True,
    'verify_nbf': True,
    'verify_iss': True,
    'verify_sub': True,
    'verify_jti': True,
    'verify_at_hash': True,
    'leeway': 0,
}

app = Flask(__name__, static_url_path='/public', static_folder='./public')
SESSION_TYPE='filesystem' 
app.config.from_object(__name__)
app.secret_key = constants.SECRET_KEY
app.debug = True
Session(app) #supports for Server-side Session. Optional

@app.errorhandler(Exception)
def handle_auth_error(ex):
    response = jsonify(message=str(ex))
    response.status_code = (ex.code if isinstance(ex, HTTPException) else 500)
    return response


oauth = OAuth(app)
auth0 = oauth.register(
    'auth0',
    client_id=AUTH0_CLIENT_ID,
    client_secret=AUTH0_CLIENT_SECRET,
    api_base_url=AUTH0_BASE_URL,
    access_token_url=AUTH0_BASE_URL + '/oauth/token',
    authorize_url=AUTH0_BASE_URL + '/authorize',
    client_kwargs={
        'scope': SCOPE
    },
)


def requires_scope(required_scope):
    """Determines if the required scope is present in the access token
    Args:
        required_scope (str): The scope required to access the resource
    """
    print(required_scope)
    def require_scope(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            token = session[TOKEN_KEY]["access_token"]
#           print(token)
            unverified_claims = jwt.get_unverified_claims(token)
            print(unverified_claims)
            if unverified_claims.get("scope"):
                token_scopes = unverified_claims["scope"].split()
                for token_scope in token_scopes:
                    if token_scope == required_scope:
                        return f(*args, **kwargs)
            raise Exception({"code": "Unauthorized", "description": "You don't have access to this resource"},403)
        return decorated
    return require_scope

#Possibly another way to authorize instead of requesting scope and checking it
#This doesn't require explicitly specifying scopes such as read:calendar and read:contacts
#Instead, depending on the user's role and permission, the permission list will be returned
#To use this, you need to enable Add Permissions in the Access Token in RBAC Settings of API setting
def requires_permission(required_permission):
    """Determines if the required permission is present in the access token
    Args:
        required_permission (str): The permission required to access the resource
    """
    print(required_permission)
    def require_permission(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            token = session[TOKEN_KEY]["access_token"]
            print(token)
            unverified_claims = jwt.get_unverified_claims(token)
            if unverified_claims.get("permissions"):
                token_permissions = unverified_claims["permissions"]
                print(token_permissions, len(token_permissions))
                for token_permission in token_permissions:
                    if token_permission == required_permission:
                        return f(*args, **kwargs)
            raise Exception({"code": "Unauthorized", "description": "You don't have access to this resource"},403)
        return decorated
    return require_permission


def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if JWT_PAYLOAD not in session:
            return redirect('/login')
        token = session[TOKEN_KEY]
        token_decoded = decode_token(token["access_token"])
       # _request_ctx_stack.top.current_user = token_decoded
        return f(*args, **kwargs)

    return decorated


# Controllers API
@app.route('/')
def home():
    return render_template('home.html')


@app.route('/callback')
def callback_handling():
    token = auth0.authorize_access_token()

    resp = auth0.get('userinfo')
    userinfo = resp.json()

    print(token)

#    token_decoded= decode_token(token["access_token"])
#    print(token_decoded)
    session[JWT_PAYLOAD] = userinfo
    session[TOKEN_KEY] = token
    return redirect('/dashboard')


@app.route('/login')
def login():
    return auth0.authorize_redirect(redirect_uri=AUTH0_CALLBACK_URL, audience=AUTH0_AUDIENCE)


@app.route('/logout')
def logout():
    session.clear()
    params = {'returnTo': url_for('home', _external=True), 'client_id': AUTH0_CLIENT_ID}
    return redirect(auth0.api_base_url + '/v2/logout?' + urlencode(params))

@app.route('/groups')
def groups():
    payload = session[JWT_PAYLOAD]
    groups = payload.get('http://seistech.nz/claims/groups')
    response = "groups: "+",".join(groups)
    return jsonify(message=response)
@app.route('/roles')
def roles():
    payload = session[JWT_PAYLOAD]
    roles = payload.get('http://seistech.nz/claims/roles')
    response = "roles: "+",".join(roles)
    return jsonify(message=response)



@app.route('/dashboard')
@requires_auth
def dashboard():
    return render_template('dashboard.html',
                           userinfo=session[JWT_PAYLOAD],
                           userinfo_pretty=json.dumps(session[JWT_PAYLOAD], indent=4))

def decode_token(token):
#    print("Gonna print the token:", file=sys.stdout)
#    print(jwt.get_unverified_header(token), file=sys.stdout)
#    print(jwt.get_unverified_claims(token), file=sys.stdout)

    jsonurl = urlopen("https://" + AUTH0_DOMAIN + "/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except Exception as e:
        raise(e)
    if unverified_header["alg"] == "HS256":
        raise Exception({"code": "invalid_header",
                         "description":
                             "Invalid header. "
                             "Use an RS256 signed JWT Access Token"}, 401)
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }

    #print(rsa_key)
    if rsa_key:
        try:
            payload = jwt.decode(token, rsa_key, algorithms=[JWT_ALGORITHM], issuer=ISSUER, audience=AUTH0_AUDIENCE, options = JWT_VERIFY_DEFAULTS)
        except jwt.ExpiredSignatureError:
            raise Exception({"code":"token_expired",
                             "description": "token is expired"}, 401)
        except jwt.JWTClaimsError:
            raise Exception({"code": "invalid_claims",
                             "description":
                                 "incorrect claims,"
                                 " please check the audience and issuer"}, 401)
        except JWTError as e:
            six.raise_from(Unauthorized, e)
        except Exception as e:
            raise Exception({"code": "invalid_header",
                             "description":
                                 "Unable to parse authentication"
                                 " token or unable to decode."}, 401)
    else:
        raise Exception({"code": "invalid_header",
                         "description": "Unable to find appropriate key"}, 401)
    return payload


@app.route("/api/public")
@cross_origin(headers=["Content-Type", "Authorization"])
def public():
    """No access token required to access this route
    """
    response = "Hello from a public endpoint! You don't need to be authenticated to see this."
    return jsonify(message=response)

@app.route("/api/private")
@cross_origin(headers=["Content-Type", "Authorization"])
@cross_origin(headers=["Access-Control-Allow-Origin", "http://localhost:3000"])
@requires_auth
def private():
    """A valid access token is required to access this route
    """
    response = "Hello from a private endpoint! You need to be authenticated to see this."
    return jsonify(message=response)

#################
# not working yet
#################
@app.route("/api/eaonly")
@cross_origin(headers=["Content-Type", "Authorization"])
@cross_origin(headers=["Access-Control-Allow-Origin", "http://localhost:3000"])
@requires_auth
@requires_scope('read:eaonly')
def read_eaonly():
    """A valid access token and an appropriate scope are required to access this route
    """
    response = "Hello! You are authorized to read ea only contents"
    return jsonify(message=response)

@app.route("/api/devonly")
@cross_origin(headers=["Content-Type", "Authorization"])
@cross_origin(headers=["Access-Control-Allow-Origin", "http://localhost:3000"])
@requires_auth
@requires_scope('read:devonly')
def read_devonly():
    """A valid access token and an appropriate scope are required to access this route
    """
    response = "Hello! You are authorized to read devonly contents"
    return jsonify(message=response)



if __name__ == "__main__":
    app.run(host='0.0.0.0', port=env.get('PORT', 3000))
