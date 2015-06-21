from flask import Flask, render_template, request, redirect, jsonify, url_for, flash

from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Region, Place, User

from flask import session
import random, string

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

import os
import sys 
import datetime
import urllib
import uuid
from PIL import Image


app = Flask(__name__)


#Connect to Database and create database session
engine = create_engine('sqlite:///travelbucketlist.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
dbsession = DBSession()

CLIENT_ID = json.loads(open('google_client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Travel Log"
DOWNLOAD_TMP_FOLDER = '/tmp/'
UPLOAD_FOLDER = './static/thumbnails/'
ALLOWED_EXTENSIONS = set(['jpg', 'jpeg'])


#JSON APIs to view Region and Place Information
@app.route('/region/<int:region_id>/place/JSON')
def regionPlaceJSON(region_id):
    region = dbsession.query(Region).filter_by(id = region_id).one()
    items = dbsession.query(Place).filter_by(region_id = region_id).all()
    return jsonify(Places=[i.serialize for i in items])

@app.route('/region/<int:region_id>/place/<int:place_id>/JSON')
def placeItemJSON(region_id, place_id):
    Place_Item = dbsession.query(Place).filter_by(id = place_id).one()
    return jsonify(Place_Item = Place_Item.serialize)

@app.route('/region/JSON')
def regionsJSON():
    regions = dbsession.query(Region).all()
    return jsonify(regions= [r.serialize for r in regions])


# Login related functions
def createUser(session):
  newUser = User(name = session['username'], email = session['email'], picture = session['picture'], allow_public_access = 1, signup_date = datetime.datetime.now())
  dbsession.add(newUser)
  dbsession.commit()
  user = dbsession.query(User).filter_by(email = session['email']).one()
  return user.id


def getUserInfo(user_id):
  user = dbsession.query(User).filter_by(id = user_id).one()
  return user


def getUserID(email):
  try:
      user = dbsession.query(User).filter_by(email = email).one()
      return user.id
  except: 
      return None


# Image saving related functions

# Check if the file has a valid picture file extension
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS

# Save the picture, creating thumbnails
def savePicture(request):
  filename = ''
  filepath = ''
  try:

    if request.form['picture_mode'] == 'web_radio':
      # File is a URL, need to download it
      if allowed_file(request.form['picture_url']):
        filename = 'tb' + str(uuid.uuid4().hex) + '.' + request.form['picture_url'].rsplit('.', 1)[1]
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        urllib.urlretrieve(request.form['picture_url'], filepath)

    elif request.form['picture_mode'] == 'disk_radio':
      # Upload file and store it
      file = request.files['file']
      if allowed_file(file.filename):
        filename = 'tb' + str(uuid.uuid4().hex) + '.' + file.filename.rsplit('.', 1)[1]
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        file.close()

    # Resize the thumbnails
    file_prefix, file_ext = os.path.splitext(filepath)

    im = Image.open(filepath)
    im.thumbnail((1200, 920))
    im.save(file_prefix + '_lg' + file_ext)

    im.thumbnail((350, 270))
    im.save(filepath)

  except:
    print "Unexpected error in SavePicture:", sys.exc_info()[0]
    filename = ''

  return filename


# Remove a picture
def removePicture(filename):
  if os.path.exists(filename):
    os.remove(filename)

  large_file = filename.rsplit('.', 1)[0] + '_lg.' + filename.rsplit('.', 1)[1]
  if os.path.exists(large_file):
    os.remove(large_file)


@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    # print "access token received %s " % access_token

    app_id = json.loads(open('facebook_client_secrets.json', 'r').read())['web']['app_id']
    app_secret = json.loads(open('facebook_client_secrets.json', 'r').read())['web']['app_secret']

    url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (
        app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]

    # Use token to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.3/me"

    # strip expire tag from access token
    token = result.split("&")[0]

    url = 'https://graph.facebook.com/v2.3/me?%s' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]

    data = json.loads(result)
    session['provider'] = 'facebook'
    session['username'] = data["name"]
    session['email'] = data["email"]
    session['facebook_id'] = data["id"]

    # The token must be stored in the session in order to properly logout, let's strip out the information before the equals sign in our token
    stored_token = token.split("=")[1]
    session['access_token'] = stored_token

    # Get user picture
    url = 'https://graph.facebook.com/v2.3/me/picture?%s&redirect=0&height=200&width=200' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    session['picture'] = data["data"]["url"]

    # see if user exists
    user_id = getUserID(session['email'])
    if not user_id:
        user_id = createUser(session)
    session['user_id'] = user_id

    output = 'redirecting...'
    return output


def fbdisconnect():
    facebook_id = session['facebook_id']
    access_token = session['access_token']
    url = 'https://graph.facebook.com/%s/permissions' % (facebook_id)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]



# Google Sign-in
@app.route('/gconnect', methods=['POST'])
def gconnect():
  if request.args.get('state') != session['state']:
    response = make_response(json.dumps('Invalid state parameter.'), 401)
    response.headers['Content-Type'] = 'application/json'
    return response
  code = request.data

  try:
    #Update the authorization code into a credentials object
    oauth_flow = flow_from_clientsecrets('google_client_secrets.json', scope='')
    oauth_flow.redirect_uri = 'postmessage'
    credentials = oauth_flow.step2_exchange(code)
  except FlowExchangeError:
    response = make_response(json.dumps('Failed to upgrade the authorization code.'), 401)
    response.headers['Content-Type'] = 'application/json'
    return response

  #Check that the access token is valid.
  access_token = credentials.access_token
  url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s' % access_token)
  h = httplib2.Http()
  result = json.loads(h.request(url, 'GET')[1])
  if result.get('error') is not None:
    response = make_response(json.dumps(result.get('error')), 500)
    response.headers['Content-Type'] = 'application/json'

  # Verify that the access token is used for the intended user.
  gplus_id = credentials.id_token['sub']
  if result['user_id'] != gplus_id:
    response = make_response(json.dumps("Token's user ID dosen't match given user ID."), 401)
    response.headers['Content-Type'] = 'application/json'
    return response

  # Verify that the access token is valid for this app.
  if result['issued_to'] != CLIENT_ID:
    response = make_response(json.dumps("Token's client ID does not match app's."), 401)
    print "Token's client ID does not match app's."
    response.headers['Content-Type'] = 'application/json'
    return response

  # Check to see if the user is already logged in
  stored_credentials = session.get('credentials')
  stored_gplus_id = session.get('gplus_id')
  if stored_credentials is not None and gplus_id == stored_gplus_id:
    response = make_response(json.dumps("Current user is already connected."), 200)
    response.headers['Content-Type'] = 'application/json'

  # Store the access token in the dbsession for later use.
  session['credentials'] = credentials.access_token
  session['gplus_id'] = gplus_id

  # Get user info
  userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
  params = {'access_token': credentials.access_token, 'alt': 'json'}
  answer = requests.get(userinfo_url, params=params)


  data = answer.json()

  session['username'] = data['name']
  session['picture'] = data['picture']
  session['email'] = data['email']
  session['provider'] = 'google'

  userid = getUserID(session['email'])
  if not userid:
    session['user_id'] = createUser(session)
  else:
    session['user_id'] = userid

  output = 'redirecting...'
  return output
  

def gdisconnect():
        # Only disconnect a connected user.
    access_token = session.get('credentials')
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]

    if result['status'] != '200':
        # For whatever reason, the given token was invalid.
        response = make_response(json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


# Disconnect based on provider
@app.route('/logout')
@app.route('/disconnect')
def disconnect():
    if 'provider' in session:
        if session['provider'] == 'google':
          gdisconnect()
          del session['gplus_id']
          del session['credentials']
        if session['provider'] == 'facebook':
            fbdisconnect()
            del session['facebook_id']
        del session['username']
        del session['email']
        del session['picture']
        del session['user_id']
        del session['provider']
        return redirect(url_for('showRegions'))
    else:
        return redirect(url_for('showRegions'))



#Login to regions app
@app.route('/login')
def showLogin():
  state = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in xrange(32))
  session['state'] = state
  return render_template('login.html', STATE=state)


#Show all regions
@app.route('/')
def showRegions():
  state = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in xrange(32))
  session['state'] = state

  regions = dbsession.query(Region).order_by(asc(Region.name))
  return render_template('regions.html', regions = regions, STATE=state)


#Create a new region
@app.route('/region/new/', methods=['GET','POST'])
def newRegion():
  if 'username' not in session:
    return redirect('/login')

  if request.method == 'POST':
      pic_filename = savePicture(request)
      newRegion = Region(name = request.form['name'], 
        user_id = session['user_id'], 
        geo_location = request.form['location'], 
        rating = int(request.form['rating']),
        picture = pic_filename)

      dbsession.add(newRegion)
      flash('New travel log "%s" created.' % newRegion.name)
      dbsession.commit()
      return redirect(url_for('showRegions'))
  else:
      return render_template('newRegion.html')


#Edit a region
@app.route('/region/<int:region_id>/edit/', methods = ['GET', 'POST'])
def editRegion(region_id):
  if 'username' not in session:
    return redirect('/login')
  
  editedRegion = dbsession.query(Region).filter_by(id = region_id).one()

  if editedRegion.user_id != session['user_id']:
    return "<script>function myFunction() {alert('You are not authorized to edit this travel log.');}</script><body onload='myFunction()'>"
    
  if request.method == 'POST':
    if request.form['name']:
      editedRegion.name = request.form['name']
    if request.form['rating']:
      editedRegion.rating = int(request.form['rating'])
    editedRegion.geo_location = request.form['location']

    if request.form['picture_mode'] and (request.form['picture_mode'] == 'disk_radio' or request.form['picture_mode'] == 'web_radio'):
      if editedRegion.picture != '':
        removePicture(UPLOAD_FOLDER + editedRegion.picture)

      editedRegion.picture = savePicture(request)

    editedRegion.modifiy_date = datetime.datetime.utcnow()
    dbsession.commit()

    flash('Saved changes to travel log "%s".' % editedRegion.name)
    return redirect(url_for('showRegion', region_id = region_id))
  else:
    return render_template('editRegion.html', region = editedRegion)


#Delete a region
@app.route('/region/<int:region_id>/delete/', methods = ['GET','POST'])
def deleteRegion(region_id):
  if 'username' not in session:
    return redirect('/login')
  
  regionToDelete = dbsession.query(Region).filter_by(id = region_id).one()

  if regionToDelete.user_id != session['user_id']:
    return "<script>function myFunction() {alert('You are not authorized to delete this travel log.');}</script><body onload='myFunction()'>"

  if request.method == 'POST':
    dbsession.delete(regionToDelete)
    flash('Travel log "%s" deleted.' % regionToDelete.name)
    dbsession.commit()
    return redirect(url_for('showRegions'))
  else:
    return render_template('deleteRegion.html',region = regionToDelete)


#Show a region's places
@app.route('/region/<int:region_id>/')
def showRegion(region_id):
  state = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in xrange(32))
  session['state'] = state

  region = dbsession.query(Region).filter_by(id = region_id).one()
  items = dbsession.query(Place).filter_by(region_id = region_id).all()
  creator = getUserInfo(region.user_id)
  return render_template('places.html', items = items, region = region, creator = creator, STATE=state)
     

#Create a new place item
@app.route('/region/<int:region_id>/place/new/',methods=['GET','POST'])
def newPlace(region_id):
  if 'username' not in session:
    return redirect('/login')
    
  region = dbsession.query(Region).filter_by(id = region_id).one()
  if request.method == 'POST':
      pic_filename = savePicture(request)
      newEntry = Place(name = request.form['name'], 
        user_id = session['user_id'],
        region_id = region_id, 
        description = request.form['description'], 
        geo_location = request.form['location'], 
        info_website = request.form['info_website'], 
        rating = int(request.form['rating']),
        picture = pic_filename)
      
      dbsession.add(newEntry)
      dbsession.commit()
      flash('New log entry created.')
      return redirect(url_for('showRegion', region_id = region_id))
  else:
      return render_template('newPlace.html', region = region, region_id = region_id)



#Edit a place item
@app.route('/region/<int:region_id>/place/<int:place_id>/edit', methods=['GET','POST'])
def editPlace(region_id, place_id):
  if 'username' not in session:
    return redirect('/login')
    
  editedItem = dbsession.query(Place).filter_by(id = place_id).one()

  if editedItem.user_id != session['user_id']:
    return "<script>function myFunction() {alert('You are not authorized to edit this log entry.');}</script><body onload='myFunction()'>"
    
  region = dbsession.query(Region).filter_by(id = region_id).one()
  if request.method == 'POST':
    if request.form['name']:
      editedItem.name = request.form['name']
    if request.form['description']:
      editedItem.description = request.form['description']
    if request.form['rating']:
      editedItem.rating = int(request.form['rating'])
    editedItem.geo_location = request.form['location']
    editedItem.info_website = request.form['info_website']

    if request.form['picture_mode'] and (request.form['picture_mode'] == 'disk_radio' or request.form['picture_mode'] == 'web_radio'):
      if editedItem.picture != '':
        removePicture(UPLOAD_FOLDER + editedItem.picture)

      editedItem.picture = savePicture(request)

    editedItem.modifiy_date = datetime.datetime.utcnow()
    dbsession.commit()

    flash('Saved changes to log entry.')
    return redirect(url_for('showRegion', region_id = region_id))
  else:
    return render_template('editPlace.html', region_id = region_id, place_id = place_id, item = editedItem)


#Delete a place item
@app.route('/region/<int:region_id>/place/<int:place_id>/delete', methods = ['GET','POST'])
def deletePlace(region_id,place_id):
  if 'username' not in session:
    return redirect('/login')
    
  region = dbsession.query(Region).filter_by(id = region_id).one()
  itemToDelete = dbsession.query(Place).filter_by(id = place_id).one() 

  if itemToDelete.user_id != session['user_id']:
    return "<script>function myFunction() {alert('You are not authorized to delete this log entry.');}</script><body onload='myFunction()'>"
  
  if request.method == 'POST':
      dbsession.delete(itemToDelete)
      dbsession.commit()
      flash('Log entry deleted.')
      return redirect(url_for('showRegion', region_id = region_id))
  else:
      return render_template('deletePlace.html', region_id = region_id, place_id = place_id, item = itemToDelete)



if __name__ == '__main__':
  app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
  app.secret_key = 'super_secret_key'
  app.debug = True
  app.run(host = '0.0.0.0', port = 5000)
