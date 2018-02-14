#!/usr/bin/env python
from flask import Flask, render_template, request, redirect, jsonify, url_for, flash
from functools import wraps
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Category, Item, User

from flask import session as login_session
import random
from random import randrange, uniform
import string

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

app = Flask(__name__)
CLIENT_ID = json.loads(
    open('client_secret.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Item Catalog App"

engine = create_engine('postgresql://catalogapp:password@localhost/catalog')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


def login_required(f):   # redirect unauthorized users to login
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' in login_session:
            return f(*args, **kwargs)
        flash("Please log in to add, edit and delete content")
        return redirect('/login')
    return decorated_function

# API endpoint to view  information in the database


@app.route('/explore')
def categoryJSON():
    categories = session.query(Category).all()
    items = session.query(Item).all()
    return jsonify(
        Categories=[
            category.serialize for category in categories], Items=[
            item.serialize for item in items])

# USER LOGIN WITH GOOGLE ACCOUNT


@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in range(32))
    # generate unique user_ids
    login_session['state'] = state
    # return "The current session state is %s" % login_session['state']
    return render_template('login.html', STATE=state)
# User Helper Functions


def createUser(login_session):
            newUser = User(name=login_session['username'], id=randrange(0, 20), email=login_session['email'],
                           picture=login_session['picture'])
            session.add(newUser)
            session.commit()
            user = session.query(User).filter_by(email=login_session['email']).one()
            return user.id


def getUserID(email):
            try:
                user = session.query(User).filter_by(email=email).one()
                return user.id
            except:
                return None
            

@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data
    
    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secret.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    
    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s' % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response
    
    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    
    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(json.dumps("Token's client ID does not match app's."), 401)
        print("Token's client ID does not match app's.")
        response.headers['Content-Type'] = 'application/json'
        return response
    
    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    
    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id
    
    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)
    
    data = answer.json()
    
    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    
    # See if a user exists, if it doesn't make a new one
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;' \
              '-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print("done!")
    return output
    

# DISCONNECT - Revoke a current user's token and reset their login_session


@app.route('/gdisconnect')
def gdisconnect():
        # Only disconnect a connected user.
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]

    # if result['status'] == '200':
    # Reset the user's sesson.
    del login_session['access_token']
    del login_session['gplus_id']
    del login_session['username']
    del login_session['email']
    del login_session['picture']
        
    flash('You have Successfully logged out')
    return redirect(url_for('showAll'))
    

# INDEX PAGE
@app.route('/')
@app.route('/home')
def showAll():
    categories = session.query(Category).order_by(asc(Category.name))
    # items = session.query(Item).filter_by(category_id=categories.id).all()
    items = session.query(Item).order_by(asc(Item.name)).slice(0, 5)
    return render_template('index-2.html', categories=categories, items=items)

# ROUTE TO VIEW ALL ITEMS IN A CATEGORY


@app.route('/category/<int:category_id>')
def getItems(category_id):
    category = session.query(Category).filter_by(id=category_id).one()
    items = session.query(Item).filter_by(category_id=category_id).all()
    return render_template('item.html', category=category, items=items)

# ROUTE TO CREATE CATEGORY


@app.route('/category/new', methods=['GET', 'POST'])
@login_required
def newCategory():
    user_id = getUserID(login_session['email'])
    if request.method == 'POST':
        newCategory = Category(name=request.form['name'], user_id=user_id)
        session.add(newCategory)
        session.commit()
        flash('New Category %s Successfully Created' % (newCategory.name))
        return redirect(url_for('showAll'))
    else:
        return render_template('newcategory.html')


# ROUTE TO DELETE CATEGORY
@app.route('/category/<int:category_id>/delete', methods=['GET', 'POST'])
@login_required
def deleteCategory(category_id):
    user_id = getUserID(login_session['email'])
    category = session.query(Category).filter_by(id=category_id).one()
    items = session.query(Item).filter_by(category_id=category_id).all()
    if category.user_id != user_id:
        flash('You cannot a delete a category you did not create, create yours')
        return redirect(url_for('showAll'))
    if request.method == 'POST':
        for item in items:
            session.delete(item)
        session.delete(category)
        session.commit()
        flash('Successfully Deleted items')
        return redirect(url_for('showAll'))
        
    else:
        return render_template('deletecategory.html', category=category)

# CREATE NEW ITEM


@app.route('/category/item/new', methods=['GET', 'POST'])
@login_required
def newItem():
    categories = session.query(Category).all()
    user_id = getUserID(login_session['email'])
    if request.method == 'POST':
        category = session.query(Category).filter_by(name=request.form['category']).one()
        newItem = Item(name=request.form['name'], description=request.form['description'], user_id=user_id, category_id=category.id)
        session.add(newItem)
        session.commit()
        flash('New Item %s Successfully Created' % newItem.name)
        return redirect(url_for('showAll'))
    else:
        return render_template('newitem.html', categories=categories)
# ROUTE TO VIEW ITEM DETAILS


@app.route('/category/item/<int:item_id>')
def viewDetails(item_id):
    item = session.query(Item).filter_by(id=item_id).one()
    return render_template('detail.html', item=item)

# ROUTE TO EDIT ITEM


@app.route('/category/item/<int:item_id>/edit', methods=['GET', 'POST'])
@login_required
def editItem(item_id):
    user_id = getUserID(login_session['email'])  # Get the user id of the currently logged in user
    categories = session.query(Category).all()
    item = session.query(Item).filter_by(id=item_id).one()
    if item.user_id != user_id:
        flash("you cannot edit an item you did not create, create yours")
        return redirect(url_for('viewDetails', item_id=item_id))
    if request.method == 'POST':
        item.name = request.form['name']
        item.description = request.form['description']
        session.add(item)
        session.commit()
        flash('Item Successfully Edited')
        return redirect(url_for('viewDetails', item_id=item_id))
    
    else:
        return render_template('edititem.html', item=item, categories=categories)

# ROUTE TO DELETE ITEM


@app.route('/category/item/<int:item_id>/delete', methods=['GET', 'POST'])
@login_required
def deleteItem(item_id):
    user_id = getUserID(login_session['email'])
    item = session.query(Item).filter_by(id=item_id).one()
    if item.user_id != user_id:
        flash("you cannot delete an item you did not create, create yours")
        return redirect(url_for('viewDetails', item_id=item_id))
    if request.method == 'POST':
       session.delete(item)
       session.commit()
       flash('Successfully Deleted')
       return redirect(url_for('showAll'))
    else:
        return render_template('deleteitem.html', item=item)


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)



