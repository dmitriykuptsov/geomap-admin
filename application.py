# -*- coding: utf-8 -*-
from flask import Flask
from flask import request, jsonify, render_template, redirect, url_for, make_response
from flask import json,Response
from flask import g
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
	# This will not work if server is behind the NAT
	return (Utils.is_ip_in_the_same_subnet(ip, subnet) or ip == "127.0.0.1");

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
	
def is_valid_session(cookie):
	return Token.is_valid(Token.decode(cookie));

def is_admin(cookie):
	query = "SELECT id FROM roles WHERE role LIKE 'admin'";
	g.cur.execute(query);
	row = g.cur.fetchone();
	return row["id"] == Token.get_role_id(Token.decode(request.cookies["token"]));

def get_default_permissions():
	query = "SELECT id, role FROM roles";
	g.cur.execute(query);
	rows = g.cur.fetchall();
	permissions = [];
	for row in rows:
		if row["role"] == "admin":
			permissions.append({"id": row["id"], "role": row["role"], "checked": True});
		else:
			permissions.append({"id": row["id"], "role": row["role"], "checked": False});
	return permissions;

def get_roles():
	query = "SELECT id, role FROM roles";
	g.cur.execute(query);
	rows = g.cur.fetchall();
	roles = [];
	for row in rows:
		roles.append(row["role"]);
	return roles;

def get_uuid():
	query = "SELECT UUID() as id";
	g.cur.execute(query);
	row = g.cur.fetchone();
	return row["id"];

def add_resource(uuid):
	query = "INSERT INTO resources(name) VALUES(%s)";
	g.cur.execute(query, [uuid]);
	g.db.commit();

def add_read_permissions(roles, permission, uuid):
	for role in roles:
		query = """
			INSERT INTO permissions(resource_id, role_id, access_right_id) 
			VALUES(
				(SELECT id FROM resources WHERE name = %s),
				(SELECT id FROM roles WHERE role = %s),
				(SELECT id FROM rights WHERE access_right = "read")
			);"""
		g.cur.execute(query, [uuid, role]);
	g.db.commit();

@app.route("/")
def default():
	return make_response(redirect("/login/"));

@app.route("/logout/")
def logout():
	response = make_response(redirect(url_for("login")));
	response.set_cookie("token", "", expires = 0);
	return response;

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
			response = make_response(redirect(url_for('areas')));
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
			return render_template("login.html", error=error);
	elif request.method == "GET":
		return render_template("login.html", error=None);

@app.route("/areas/", methods=["GET", "POST"])
def areas():
	if not ip_based_access_control(request.remote_addr, "192.168.0.0"):
		return make_response(redirect(url_for("login")));
	if not is_valid_session(request.cookies["token"]):
		return make_response(redirect(url_for("login")));
	if not is_admin(request.cookies["token"]):
		return make_response(redirect(url_for("login")));
	role_id = Token.get_role_id(Token.decode(request.cookies["token"]));
	if request.method == "GET":
		region_id = request.args.get("region_id", None);
		query = """SELECT a.id, a.region_id, a.area_id, a.name_ru FROM areas a 
				INNER JOIN permissions p 
				ON p.resource_id = a.resource_id
				WHERE a.area_id = 0 AND p.role_id = %s
				AND p.access_right_id = (SELECT r.id FROM rights r WHERE r.access_right = "read")
				""";
		g.cur.execute(query, [role_id]);
		rows = g.cur.fetchall();
		regions = [];
		areas = [];
		if not region_id:
			region_id = rows[0]["region_id"];
		for row in rows:
			if row["region_id"] == int(region_id):
				regions.insert(0, {
					"id": row["id"], 
					"name": row["name_ru"], 
					"region_id": row["region_id"]
				});
			else:
				regions.append({
					"id": row["id"], 
					"name": row["name_ru"], 
					"region_id": row["region_id"]
				});
		query = """
				SELECT a.id, a.name_ru, a.area_id, a.region_id FROM areas a 
				INNER JOIN permissions p
				ON p.resource_id = a.resource_id
				WHERE a.region_id = %s AND a.area_id <> 0 AND p.role_id = %s
				AND p.access_right_id = (SELECT r.id FROM rights r WHERE r.access_right = "read")
				""";
		g.cur.execute(query, [int(region_id), role_id]);
		rows = g.cur.fetchall();
		#print(g.cur._last_executed);
		for row in rows:
			areas.append({
				"id": row["id"], 
				"name": row["name_ru"], 
				"area_id": row["area_id"], 
				"region_id": row["region_id"]
				});
		return render_template("areas.html", regions = regions, areas = areas);
	else:
		return redirect(url_for('login'));

@app.route("/delete_area/", methods=["GET"])
def delete_area():
	if not ip_based_access_control(request.remote_addr, "192.168.0.0"):
		return make_response(redirect(url_for("login")));
	if not is_valid_session(request.cookies["token"]):
		return make_response(redirect(url_for("login")));
	"""
	If user is admin, then he/she can delete, create and modify all records already
	"""
	if not is_admin(request.cookies["token"]):
		return make_response(redirect(url_for("login")));
	role_id = Token.get_role_id(Token.decode(request.cookies["token"]));
	region_id = request.args.get("region_id", None);
	area_id = request.args.get("area_id", None);
	if not region_id or not area_id:
		return make_response(redirect(url_for("areas")));
	query = "DELETE FROM areas WHERE region_id = %s AND area_id = %s";
	g.cur.execute(query, [int(region_id), int(area_id)]);
	g.db.commit();
	return make_response(redirect(url_for("areas")));

@app.route("/add_area/", methods=["GET", "POST"])
def add_area():
	if not ip_based_access_control(request.remote_addr, "192.168.0.0"):
		return make_response(redirect(url_for("login")));
	if not is_valid_session(request.cookies["token"]):
		return make_response(redirect(url_for("login")));
	"""
	If user is admin, then he/she can delete, create and modify all records already
	"""
	if not is_admin(request.cookies["token"]):
		return make_response(redirect(url_for("login")));
	role_id = Token.get_role_id(Token.decode(request.cookies["token"]));
	if request.method == "GET":
		query = """SELECT a.id, a.region_id, a.area_id, a.name_ru FROM areas a 
				INNER JOIN permissions p 
				ON p.resource_id = a.resource_id
				WHERE a.area_id = 0 AND p.role_id = %s
				AND p.access_right_id = (SELECT r.id FROM rights r WHERE r.access_right = "read")
				""";
		g.cur.execute(query, [role_id]);
		rows = g.cur.fetchall();
		regions = [];
		for row in rows:
			regions.append({
				"id": row["id"], 
				"name": row["name_ru"], 
				"region_id": row["region_id"]
			});
		return render_template("add_area.html", 
			regions = regions, 
			permissions = get_default_permissions(), 
			error = None);
	elif request.method == "POST":
		region_id = request.form.get("region_id", None);
		area_name = request.form.get("area", None);
		if not region_id:
			query = """SELECT a.id, a.region_id, a.area_id, a.name_ru FROM areas a 
				INNER JOIN permissions p 
				ON p.resource_id = a.resource_id
				WHERE a.area_id = 0 AND p.role_id = %s
				AND p.access_right_id = (SELECT r.id FROM rights r WHERE r.access_right = "read")
				""";
			g.cur.execute(query, [role_id]);
			rows = g.cur.fetchall();
			regions = [];
			for row in rows:
				regions.append({
					"id": row["id"], 
					"name": row["name_ru"], 
					"region_id": row["region_id"]
				});
			return render_template("add_area.html", 
				regions = regions, 
				permissions = get_default_permissions(), 
				error = u"Неверный код области");

		#Make regular expression here
		if not area_name or area_name == "":
			query = """SELECT a.id, a.region_id, a.area_id, a.name_ru FROM areas a 
				INNER JOIN permissions p 
				ON p.resource_id = a.resource_id
				WHERE a.area_id = 0 AND p.role_id = %s
				AND p.access_right_id = (SELECT r.id FROM rights r WHERE r.access_right = "read")
				""";
			g.cur.execute(query, [role_id]);
			rows = g.cur.fetchall();
			regions = [];
			for row in rows:
				regions.append({
					"id": row["id"], 
					"name": row["name_ru"], 
					"region_id": row["region_id"]
				});
			return render_template("add_area.html", 
				regions = regions, 
				permissions = get_default_permissions(), 
				error = u"Неверное наименование для района");
		roles = get_roles();

		return make_response(redirect(url_for("areas")));
if __name__ == "__main__":
	app.run();