# -*- coding: utf-8 -*-
from flask import Flask
from flask import request, jsonify, render_template, redirect, url_for, make_response
from flask import json,Response
from flask import g
#from flask_cors import CORS
from logging.config import dictConfig
import numpy as np
import decimal
import MySQLdb
import hashlib
import random
import datetime
import os
import re
import sys
import json
import base64
import atexit
import traceback
from config import config
from tokens import Token
from utils import Utils
from helpers import LoginStatus

app = Flask(__name__);
#CORS(app);

# This is too large but anyways 
random.seed(os.urandom(64));

def connect_to_database():
	return MySQLdb.connect(host=config["DB_HOST"],
		user=config["DB_USER"],
		passwd=config["DB_PASSWORD"],
		db=config["DB"],
		charset="utf8");

@app.before_request
def db_connect():
	g.db = connect_to_database();
	g.cur = g.db.cursor(MySQLdb.cursors.DictCursor);

@app.teardown_request
def db_disconnect(exception=None):
	g.db.close();

def exit_handler():
	"""
	Perform graceful shutdown
	"""
	g.db.close();

atexit.register(exit_handler);

def ip_based_access_control(ip, subnet):
	return (Utils.is_ip_in_the_same_subnet(ip, subnet) | ip == "127.0.0.1");

def valid_login(username, password):
	if not re.match("^[a-z0-9]{5,100}$", username):
		return LoginStatus(False, None, None);
	if not re.match("^(?=.*[A-Z]+)(?=.*[a-z]+)(?=.*[0-9]+)(?=.*[$#%]+)", password) or \
		not re.match("^[a-zA-Z0-9#$%&@]{10,100}$", password):
		return LoginStatus(False, None, None);
	
	query = """SELECT u.id AS user_id, u.role_id, r.role FROM users u 
		INNER JOIN roles r ON r.id = u.role_id 
		WHERE u.username = %s AND u.password = SHA2((%s), 256) AND enabled = TRUE;""";
	g.cur.execute(query, [username, password + config["PASSWORD_SALT"]]);
	row = g.cur.fetchone();
	if not row:
		return LoginStatus(False, None, None);
	role_id = row["role_id"];
	user_id = row["user_id"];
	return LoginStatus(True, role_id, user_id)
	
@app.route("/")
def default():
	return redirect("/login/")

@app.route("/login/", methods=["GET", "POST"])
def login():
	if not ip_based_access_control(request.remote_addr, "192.168.0.0"):
		return redirect(url_for('login'));
	if request.method == "POST":
		login_status = valid_login(request.form["username"], request.form["password"]);
		if login_status.success:
			expire_date = datetime.datetime.utcnow() + \
				datetime.timedelta(seconds=config["MAX_SESSION_DURATION_IN_SECONDS"])
			random_token = Utils.token_hex();
			response = make_response(redirect(url_for('admin')));
			response.set_cookie(
				"token", 
				Token.encode(
					login_status.role_id, 
					login_status.user_id, 
					random_token,
					config["SERVER_NONCE"],
					config["MAX_SESSION_DURATION_IN_SECONDS"]), 
				secure=False,
				httponly=True,
				expires=expire_date,
				samesite="Strict");
			return response
		else:
			error = u"Неверное имя пользователя или пароль";
			return render_template('login.html', error=error);
	elif request.method == "GET":
		return render_template('login.html', error=None);

@app.route("/admin/", methods=["GET", "POST"])
def admin():
	if not ip_based_access_control(request.remote_addr, "192.168.0.0"):
		return redirect(url_for('login'));
	return render_template('admin.html');

if __name__ == "__main__":
	app.run();