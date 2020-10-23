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
from werkzeug._compat import BytesIO

app = Flask(__name__);

app.config['MAX_CONTENT_LENGTH'] = 30 * 1024 * 1024;

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

"""
Grants access only to local network users.
"""
def ip_based_access_control(ip, subnet, default_gw = "192.168.0.1"):
	# This will not work if server is in DMZ
	#return ((Utils.is_ip_in_the_same_subnet(ip, subnet) or ip == "127.0.0.1") and ip != default_gw);
	return True

"""
Verifies username and password. If login is valid 
role and user IDs are returned.
"""
def valid_login(username, password):
	if not re.match("^[a-z0-9]{5,100}$", username):
		return (False, None, None);
	if not re.match("^(?=.*[A-Z]+)(?=.*[a-z]+)(?=.*[0-9]+)(?=.*[$#%]+)", password) or \
		not re.match("^[a-zA-Z0-9#$%&@]{10,100}$", password):
		return (False, None, None);
	query = """SELECT u.id AS user_id, u.role_id, r.role FROM users u 
		INNER JOIN roles r ON r.id = u.role_id 
		WHERE u.username = %s AND u.password = SHA2((%s), 256) AND enabled = TRUE;""";
	g.cur.execute(query, [username, password + config["PASSWORD_SALT"]]);
	row = g.cur.fetchone();
	if not row:
		return (False, None, None);
	role_id = row["role_id"];
	user_id = row["user_id"];
	return (True, role_id, user_id);
	
"""
Checks whether the session is valid
"""
def is_valid_session(cookie):
	return Token.is_valid(Token.decode(cookie));

"""
Checks if the user is admin
"""
def is_admin(cookie):
	query = "SELECT id FROM roles WHERE role = 'admin'";
	g.cur.execute(query);
	row = g.cur.fetchone();
	if not row:
		return False;
	return row["id"] == Token.get_role_id(Token.decode(cookie));

"""
Checks whether the token is the same in cookie and and in request arguments
"""
def is_valid_hash(cookie, hash):
	return Token.get_token_hash(Token.decode(cookie)) == hash;

def get_hash(cookie):
	return Token.get_token_hash(Token.decode(cookie));

""" 
Get submitted roles from form
"""
def get_roles_from_form(form, roles):
	permitted_roles = [];
	for role in roles:
		if form.get(role, None):
			permitted_roles.append(role);
	return permitted_roles;

"""
Gets the region by id
"""
def get_region(region_id):
	query = """
		SELECT a.id, a.region_id, a.name_ru 
		FROM areas a 
		WHERE a.region_id = %s AND a.area_id = 0
	"""
	g.cur.execute(query, [region_id]);
	row = g.cur.fetchone();
	if not row:
		return None;
	else:
		return {"region_id": row["region_id"], "name": row["name_ru"]};

"""
Returns a list of regions
"""
def get_regions():
	query = """
		SELECT a.id, a.region_id, a.area_id, a.name_ru 
			FROM areas a 
				WHERE a.area_id = 0 ORDER BY a.name_ru ASC
		""";
	g.cur.execute(query);
	rows = g.cur.fetchall();
	regions = [];
	for row in rows:
		regions.append({
			"id": row["id"], 
			"name": row["name_ru"], 
			"region_id": row["region_id"]
		});
	return regions;

def get_deposit_kinds():
	query = """
		SELECT dt.id, dt.kind_id, dt.name_ru 
			FROM deposit_types dt
			WHERE dt.kind_id <> 0
				AND dt.group_id = 0
				AND dt.type_id = 0
				AND dt.subtype_id = 0
	"""
	g.cur.execute(query);
	rows = g.cur.fetchall();
	deposit_kinds = [];
	for row in rows:
		deposit_kinds.append({
			"id": row["id"], 
			"name": row["name_ru"], 
			"kind_id": row["kind_id"]
		});
	return deposit_kinds;

def get_deposit_kinds_all():
	query = """
		SELECT dt.id, dt.kind_id, dt.name_ru 
			FROM deposit_types dt
			WHERE dt.kind_id <> 0
				AND dt.group_id = 0
				AND dt.type_id = 0
				AND dt.subtype_id = 0
	"""
	g.cur.execute(query);
	rows = g.cur.fetchall();
	deposit_kinds = [{
			"id": 0, 
			"name": u"Не выбран", 
			"kind_id": 0
		}];
	for row in rows:
		deposit_kinds.append({
			"id": row["id"], 
			"name": row["name_ru"], 
			"kind_id": row["kind_id"]
		});
	return deposit_kinds;

def get_deposit_groups(deposit_kind_id):
	query = """
		SELECT dt.id, dt.kind_id, dt.group_id, dt.name_ru 
			FROM deposit_types dt
			WHERE dt.kind_id = %s
				AND dt.group_id <> 0
				AND dt.type_id = 0
				AND dt.subtype_id = 0
	"""
	g.cur.execute(query, [deposit_kind_id]);
	rows = g.cur.fetchall();
	deposit_groups = [];
	for row in rows:
		deposit_groups.append({
			"id": row["id"], 
			"name": row["name_ru"], 
			"kind_id": row["kind_id"],
			"group_id": row["group_id"]
		});
	return deposit_groups;


def get_deposit_types(deposit_kind_id, deposit_group_id):
	query = """
		SELECT dt.id, dt.kind_id, dt.group_id, dt.type_id, dt.name_ru 
			FROM deposit_types dt
			WHERE dt.kind_id = %s
				AND dt.group_id = %s
				AND dt.type_id <> 0
				AND dt.subtype_id = 0
	"""
	g.cur.execute(query, [deposit_kind_id, deposit_group_id]);
	rows = g.cur.fetchall();
	deposit_types = [];
	for row in rows:
		deposit_types.append({
			"id": row["id"], 
			"name": row["name_ru"], 
			"kind_id": row["kind_id"],
			"group_id": row["group_id"],
			"type_id": row["type_id"]
		});
	return deposit_types;


def get_amount_units():
	query = """
		SELECT id, name_ru
			FROM amount_units
				ORDER BY name_ru ASC
	""";
	g.cur.execute(query);
	rows = g.cur.fetchall();
	amount_units = [];
	for row in rows:
		amount_units.append({
			"amount_unit_id": row["id"], 
			"name": row["name_ru"]
		});
	return amount_units;

def get_minerals(amount_unit_id):
	query = """
		SELECT id, name_ru
			FROM minerals
				WHERE amount_unit_id = %s
				ORDER BY name_ru ASC
	""";
	g.cur.execute(query, [amount_unit_id]);
	rows = g.cur.fetchall();
	minerals = [];
	for row in rows:
		minerals.append({
			"mineral_id": row["id"], 
			"name": row["name_ru"]
		});
	return minerals;

def get_minerals_all():
	query = """
		SELECT id, name_ru
			FROM minerals
				ORDER BY name_ru ASC
	""";
	g.cur.execute(query, []);
	rows = g.cur.fetchall();
	minerals = [];
	for row in rows:
		minerals.append({
			"mineral_id": row["id"], 
			"name": row["name_ru"]
		});
	return minerals;

def get_statuses():
	query = """
		SELECT id, name_ru
			FROM deposit_status
				ORDER BY name_ru ASC
	""";
	g.cur.execute(query, []);
	rows = g.cur.fetchall();
	statuses = [];
	for row in rows:
		statuses.append({
			"status_id": row["id"], 
			"name": row["name_ru"]
		});
	return statuses;

def get_sites():
	query = """
		SELECT id, name_ru
			FROM sites
				ORDER BY name_ru ASC
	""";
	g.cur.execute(query);
	rows = g.cur.fetchall();
	sites = [];
	for row in rows:
		sites.append({
			"id": row["id"], 
			"name": row["name_ru"]
		});
	return sites;

def get_licenses():
	query = """
		SELECT l.id AS license_id, l.license, l.date_of_issue, c.name_ru AS company_name
			FROM licenses l 
				INNER JOIN companies c ON l.company_id = c.id ORDER BY l.license ASC
	"""
	g.cur.execute(query);
	rows = g.cur.fetchall();
	licenses = [];
	for row in rows:
		licenses.append({
			"id": row["license_id"], 
			"license": row["license"],
			"date_of_issue": row["date_of_issue"],
			"company_name": row["company_name"]
		});
	return licenses;

def get_companies(partial_company_name):
	partial_company_name = "%" + partial_company_name + "%";
	query = """
		SELECT id, name_ru FROM companies
			WHERE UPPER(name_ru) LIKE UPPER(%s)
				ORDER BY name_ru ASC
	"""
	g.cur.execute(query, [partial_company_name]);
	rows = g.cur.fetchall();
	companies = [];
	for row in rows:
		companies.append({
			"id": row["id"],
			"name": row["name_ru"]
			});		
	return companies;

def get_licenses_by_name(partial_license):
	partial_license = "%" + partial_license + "%";
	query = """
		SELECT l.id, CONCAT(l.license, ', ', c.name_ru) AS license FROM licenses l
			INNER JOIN companies c ON c.id = l.company_id
			WHERE UPPER(CONCAT(l.license, ', ', c.name_ru)) LIKE UPPER(%s) 
	"""
	g.cur.execute(query, [partial_license]);
	rows = g.cur.fetchall();
	licenses = [];
	for row in rows:
		licenses.append({
			"id": row["id"],
			"name": row["license"]
			});
	return licenses;

def get_deposit_site_type_by_name(partial_name):
	partial_name = "%" + partial_name + "%";
	query = """
		SELECT dst.id, CONCAT(d.name_ru, ' (', s.name_ru, ')', ' - ', m.name_ru) AS name FROM deposits_sites_types dst
			INNER JOIN deposits_sites ds ON ds.id = deposit_site_id
			INNER JOIN deposits d ON d.id = ds.deposit_id
			INNER JOIN sites s ON s.id = ds.site_id
			INNER JOIN minerals m ON m.id = ds.minerals_id
			WHERE UPPER(CONCAT(d.name_ru, ' (', s.name_ru, ')', ' - ', m.name_ru)) LIKE UPPER(%s)
	""";
	g.cur.execute(query, [partial_name]);
	rows = g.cur.fetchall();
	deposits_sites_types = [];
	for row in rows:
		deposits_sites_types.append({
			"id": row["id"],
			"name": row["name"]
			});
	return deposits_sites_types;

def get_deposits_by_name(partial_deposit_name):
	partial_deposit_name = "%" + partial_deposit_name + "%";
	query = """
		SELECT id, name_ru FROM deposits
			WHERE UPPER(name_ru) LIKE UPPER(%s)
				ORDER BY name_ru ASC
	"""
	g.cur.execute(query, [partial_deposit_name]);
	rows = g.cur.fetchall();
	deposits = [];
	for row in rows:
		deposits.append({
			"id": row["id"],
			"name": row["name_ru"]
			});		
	return deposits;

def get_sites_by_name(partial_site_name):
	partial_site_name = "%" + partial_site_name + "%";
	query = """
		SELECT id, name_ru FROM sites
			WHERE UPPER(name_ru) LIKE UPPER(%s)
				ORDER BY name_ru ASC
	"""
	g.cur.execute(query, [partial_site_name]);
	rows = g.cur.fetchall();
	sites = [];
	for row in rows:
		sites.append({
			"id": row["id"],
			"name": row["name_ru"]
			});		
	return sites;

def get_deposits_sites_by_name(partial_deposit_site_name):
	partial_deposit_site_name = "%" + partial_deposit_site_name + "%";
	query = """
		SELECT ds.id, CONCAT(d.name_ru, IF(s.name_ru <> "", CONCAT(" (", s.name_ru, ")"), "")) AS name_ru FROM deposits_sites ds
			INNER JOIN deposits d ON d.id = ds.deposit_id
			INNER JOIN sites s ON s.id = ds.site_id
			WHERE UPPER(CONCAT(d.name_ru, "(", s.name_ru, ")")) LIKE UPPER(%s)
				ORDER BY CONCAT(d.name_ru, "(", s.name_ru, ")") ASC
	"""
	g.cur.execute(query, [partial_deposit_site_name]);
	rows = g.cur.fetchall();
	sites = [];
	for row in rows:
		sites.append({
			"id": row["id"],
			"name": row["name_ru"]
			});		
	return sites;

def get_minerals_by_name(partial_mineral_name):
	partial_mineral_name = "%" + partial_mineral_name + "%";
	query = """
		SELECT m.id, m.name_ru FROM minerals m
			WHERE UPPER(m.name_ru) LIKE UPPER(%s)
				ORDER BY m.name_ru ASC
	"""
	g.cur.execute(query, [partial_mineral_name]);
	rows = g.cur.fetchall();
	minerals = [];
	for row in rows:
		minerals.append({
			"id": row["id"],
			"name": row["name_ru"]
			});		
	return minerals;

def get_deposits_sites_types_by_name(partial_deposit_site_name):
	partial_deposit_site_name = "%" + partial_deposit_site_name + "%";
	query = """
		SELECT dst.id, CONCAT(d.name_ru, IF(s.name_ru <> "", CONCAT(" (", s.name_ru, ")"), ""), " - ", m.name_ru) AS name_ru FROM deposits_sites_types dst
			INNER JOIN deposits_sites ds ON ds.id = dst.deposit_site_id
			INNER JOIN deposits d ON d.id = ds.deposit_id
			INNER JOIN sites s ON s.id = ds.site_id
			INNER JOIN minerals m ON m.id = dst.minerals_id
			WHERE UPPER(CONCAT(d.name_ru, "(", s.name_ru, ")")) LIKE UPPER(%s)
				ORDER BY CONCAT(d.name_ru, "(", s.name_ru, ")") ASC
	"""
	g.cur.execute(query, [partial_deposit_site_name]);
	rows = g.cur.fetchall();
	sites = [];
	for row in rows:
		sites.append({
			"id": row["id"],
			"name": row["name_ru"]
			});		
	return sites;

def get_deposits():
	query = """
		SELECT d.id, d.name_ru FROM deposits d ORDER BY name_ru ASC
	""";
	g.cur.execute(query);
	rows = g.cur.fetchall();
	deposits = [];
	for row in rows:
		deposits.append({
			"deposit_id": row["id"],
			"name": row["name_ru"]
			});
	return deposits;

def get_deposits_sites():
	query = """
		SELECT ds.id, d.name_ru AS deposit_name, s.name_ru AS site_name
			FROM deposits_sites ds 
				INNER JOIN deposits d ON d.id = ds.deposit_id
				INNER JOIN sites s ON s.id = ds.site_id 
					ORDER BY d.name_ru ASC
	""";
	g.cur.execute(query);
	rows = g.cur.fetchall();
	deposits_sites = [];
	for row in rows:
		deposits_sites.append({
			"deposit_site_id": row["id"],
			"deposit_name": row["deposit_name"],
			"site_name": row["site_name"]
			});
	return deposits_sites;

def get_deposits_sites_types():
	query = """
	SELECT dst.id, d.name_ru AS deposit_name, s.name_ru AS site_name, 
		(SELECT dtdt.name_ru FROM deposit_types dtdt WHERE dtdt.kind_id = 
			(SELECT dtdtdt.kind_id FROM deposit_types dtdtdt WHERE dtdtdt.id=dst.type_group_id) 
			AND dtdt.group_id = 0 AND dtdt.type_id=0 AND dtdt.subtype_id=0) AS kind_name, 
		(SELECT dtdt.name_ru FROM deposit_types dtdt WHERE dtdt.kind_id = 
			(SELECT dtdtdt.kind_id FROM deposit_types dtdtdt WHERE dtdtdt.id=dst.type_group_id) 
			AND dtdt.group_id = (SELECT dtdtdt.group_id FROM deposit_types AS dtdtdt WHERE dtdtdt.id=dst.type_group_id) 
			AND dtdt.type_id=0 AND dtdt.subtype_id=0) AS group_name, 
		(SELECT dtdt.name_ru FROM deposit_types dtdt WHERE dtdt.kind_id = 
			(SELECT dtdtdt.kind_id FROM deposit_types dtdtdt WHERE dtdtdt.id=dst.type_group_id) 
			AND dtdt.group_id = (SELECT dtdtdt.group_id FROM deposit_types AS dtdtdt WHERE dtdtdt.id=dst.type_group_id) 
			AND dtdt.type_id = (SELECT dtdtdt.type_id FROM deposit_types AS dtdtdt WHERE dtdtdt.id=dst.type_group_id) 
			AND dtdt.subtype_id=0) AS type_name,
		(SELECT dtdt.name_ru FROM deposit_types dtdt WHERE dtdt.kind_id = 
			(SELECT dtdtdt.kind_id FROM deposit_types dtdtdt WHERE dtdtdt.id=dst.type_group_id) 
			AND dtdt.group_id = (SELECT dtdtdt.group_id FROM deposit_types AS dtdtdt WHERE dtdtdt.id=dst.type_group_id) 
			AND dtdt.type_id = (SELECT dtdtdt.type_id FROM deposit_types AS dtdtdt WHERE dtdtdt.id=dst.type_group_id) 
			AND dtdt.subtype_id=(SELECT dtdtdt.subtype_id FROM deposit_types AS dtdtdt WHERE dtdtdt.id=dst.type_group_id)) AS subtype_name,
		m.name_ru AS mineral
		FROM deposits_sites_types dst 
		INNER JOIN deposits_sites ds ON dst.deposit_site_id = ds.id 
		INNER JOIN deposits d ON d.id=ds.deposit_id 
		INNER JOIN sites s ON s.id = ds.site_id 
		INNER JOIN minerals m ON m.id = dst.minerals_id;
	"""
	g.cur.execute(query);
	rows = g.cur.fetchall();
	deposits_sites_types = [];
	for row in rows:
		deposits_sites_types.append({
			"deposit_site_type_id": row["id"],
			"deposit_name": row["deposit_name"],
			"site_name": row["site_name"],
			"kind_name": row["kind_name"],
			"group_name": row["group_name"],
			"type_name": row["type_name"],
			"subtype_name": row["subtype_name"],
			"mineral": row["mineral"]
			});
	return deposits_sites_types;


def get_deposits_sites_licenses():
	query = """
		SELECT dsl.id, d.name_ru AS deposit_name, s.name_ru as site_name, 
			l.license,
			(SELECT dtdt.name_ru FROM deposit_types dtdt 
				WHERE dtdt.kind_id = dt.kind_id AND dtdt.group_id = 0 AND dtdt.type_id = 0 AND dtdt.subtype_id = 0) AS kind_name, 
			(SELECT dtdt.name_ru FROM deposit_types dtdt 
				WHERE dtdt.kind_id = dt.kind_id AND dtdt.group_id = dt.group_id AND dtdt.type_id = 0 AND dtdt.subtype_id = 0) AS group_name, 
			(SELECT dtdt.name_ru FROM deposit_types dtdt 
				WHERE dtdt.kind_id = dt.kind_id AND dtdt.group_id = dt.group_id AND dtdt.type_id = dt.type_id AND dtdt.subtype_id = 0) AS type_name 
		FROM deposits_sites_licenses dsl 
		INNER JOIN deposits_sites_types dst ON dst.id = dsl.deposit_site_type_id 
		INNER JOIN deposits_sites ds ON ds.id = dst.deposit_site_id 
		INNER JOIN deposits d ON d.id = ds.deposit_id 
		INNER JOIN sites s ON s.id = ds.site_id 
		INNER JOIN deposit_types dt ON dt.id = dst.type_group_id
		INNER JOIN licenses l ON l.id = dsl.license_id;
	""";

	g.cur.execute(query);
	rows = g.cur.fetchall();
	deposits_sites_licenses = [];
	for row in rows:
		deposits_sites_licenses.append({
			"deposit_site_license_id": row["id"],
			"deposit_name": row["deposit_name"],
			"site_name": row["site_name"],
			"kind_name": row["kind_name"],
			"group_name": row["group_name"],
			"type_name": row["type_name"],
			"license": row["license"]
			});
	return deposits_sites_licenses;

def get_deposits_sites_contours():
	query = "SET GLOBAL sql_mode=(SELECT REPLACE(@@sql_mode,'ONLY_FULL_GROUP_BY',''));";
	g.cur.execute(query);
	query = """
		SELECT dsc.deposit_site_type_id, d.name_ru AS deposit_name, s.name_ru as site_name, 
			(SELECT dtdt.name_ru FROM deposit_types dtdt 
				WHERE dtdt.kind_id = dt.kind_id AND dtdt.group_id = 0 AND dtdt.type_id = 0 AND dtdt.subtype_id = 0) AS kind_name, 
			(SELECT dtdt.name_ru FROM deposit_types dtdt 
				WHERE dtdt.kind_id = dt.kind_id AND dtdt.group_id = dt.group_id AND dtdt.type_id = 0 AND dtdt.subtype_id = 0) AS group_name, 
			(SELECT dtdt.name_ru FROM deposit_types dtdt 
				WHERE dtdt.kind_id = dt.kind_id AND dtdt.group_id = dt.group_id AND dtdt.type_id = dt.type_id AND dtdt.subtype_id = 0) AS type_name,
			m.name_ru AS mineral_name
		FROM deposit_site_contours dsc
		INNER JOIN deposits_sites_types dst ON dst.id = dsc.deposit_site_type_id 
		INNER JOIN deposits_sites ds ON ds.id = dst.deposit_site_id 
		INNER JOIN deposits d ON d.id = ds.deposit_id 
		INNER JOIN sites s ON s.id = ds.site_id 
		INNER JOIN minerals m ON m.id = dst.minerals_id
		INNER JOIN deposit_types dt ON dt.id = dst.type_group_id
		GROUP BY dsc.deposit_site_type_id;
	""";
	g.cur.execute(query);
	rows = g.cur.fetchall();
	deposits_sites_contours = [];
	print(len(rows));
	for row in rows:
		deposits_sites_contours.append({
			"deposit_site_type_id": row["deposit_site_type_id"],
			"deposit_name": row["deposit_name"],
			"site_name": row["site_name"],
			"kind_name": row["kind_name"],
			"group_name": row["group_name"],
			"type_name": row["type_name"],
			"mineral_name": row["mineral_name"]
			});
	return deposits_sites_contours;

"""
Returns area
"""
def get_area(region_id, area_id):
	query = """
		SELECT name_ru 
			FROM areas 
				WHERE region_id = %s 
					AND area_id = %s
	""";
	g.cur.execute(query, [region_id, area_id]);
	row = g.cur.fetchone();
	if not row:
		return None;
	return row["name_ru"];


"""
Gets amount unit name by ID
"""
def get_amount_unit(amount_unit_id):
	query = "SELECT name_ru FROM amount_units WHERE id = %s";
	g.cur.execute(query, [amount_unit_id]);
	row = g.cur.fetchone();
	if not row:
		return None;
	return row["name_ru"];

def get_mineral(mineral_id):
	query = "SELECT name_ru FROM minerals WHERE id = %s";
	g.cur.execute(query, [mineral_id]);
	row = g.cur.fetchone();
	if not row:
		return None;
	return row["name_ru"];

def get_deposit_status(deposit_status_id):
	query = "SELECT name_ru FROM deposit_status WHERE id = %s";
	g.cur.execute(query, [deposit_status_id]);
	row = g.cur.fetchone();
	if not row:
		return None;
	return row["name_ru"];

"""
Gets deposit kind name by ID
"""
def get_deposit_kind(deposit_kind_id):
	query = """
		SELECT name_ru FROM deposit_types
			WHERE kind_id = %s 
				AND group_id = 0
				AND type_id = 0
				AND subtype_id = 0
	""";
	g.cur.execute(query, [deposit_kind_id]);
	row = g.cur.fetchone();
	if not row:
		return None;
	return row["name_ru"];

"""
Gets deposit group name by ID
"""
def get_deposit_group(deposit_kind_id, deposit_group_id):
	query = """
		SELECT name_ru FROM deposit_types
			WHERE kind_id = %s 
				AND group_id = %s
				AND type_id = 0
				AND subtype_id = 0
	""";
	g.cur.execute(query, [deposit_kind_id, deposit_group_id]);
	row = g.cur.fetchone();
	if not row:
		return None;
	return row["name_ru"];

"""
Gets deposit type name by ID
"""
def get_deposit_type(
	deposit_kind_id, 
	deposit_group_id, 
	deposit_type_id):
	query = """
		SELECT name_ru FROM deposit_types
			WHERE kind_id = %s 
				AND group_id = %s
				AND type_id = %s
				AND subtype_id = 0
	""";
	g.cur.execute(query, [deposit_kind_id, 
		deposit_group_id, deposit_type_id]);
	row = g.cur.fetchone();
	if not row:
		return None;
	return row["name_ru"];


"""
Gets deposit subtype name by ID
"""
def get_deposit_subtype(
	deposit_kind_id, 
	deposit_group_id, 
	deposit_type_id,
	deposit_subtype_id):
	query = """
		SELECT name_ru FROM deposit_types
			WHERE kind_id = %s 
				AND group_id = %s
				AND type_id = %s
				AND subtype_id = %s
	""";
	g.cur.execute(query, [deposit_kind_id, 
		deposit_group_id, deposit_type_id,
		deposit_subtype_id]);
	row = g.cur.fetchone();
	if not row:
		return None;
	return row["name_ru"];

def get_company(company_id):
	query = """
		SELECT name_ru FROM companies
			WHERE id = %s 
	""";
	g.cur.execute(query, [company_id]);
	row = g.cur.fetchone();
	if not row:
		return None;
	return row["name_ru"];

def get_site(site_id):
	query = """
		SELECT name_ru FROM sites
			WHERE id = %s 
	""";
	g.cur.execute(query, [site_id]);
	row = g.cur.fetchone();
	if not row:
		return None;
	return row["name_ru"];

def get_deposit(deposit_id):
	query = """
		SELECT name_ru FROM deposits
			WHERE id = %s
	"""
	g.cur.execute(query, [deposit_id]);
	row = g.cur.fetchone();
	if not row:
		return None;
	return row["name_ru"];	

def get_areas(region_id):
	query = """
		SELECT area_id, region_id, name_ru FROM areas
			WHERE region_id = %s AND area_id <> 0 ORDER BY name_ru ASC
	"""
	g.cur.execute(query, [region_id]);
	rows = g.cur.fetchall();
	areas = [];
	for row in rows:
		areas.append({
			"region_id": row["region_id"],
			"area_id": row["area_id"],
			"name": row["name_ru"]
			});
	return areas;

def get_license(license_id):
	query = """
		SELECT license FROM licenses
			WHERE id = %s 
	""";
	g.cur.execute(query, [license_id]);
	row = g.cur.fetchone();
	if not row:
		return None;
	return row["license"];

def get_license_date_of_issue(license_id):
	query = """
		SELECT date_of_issue FROM licenses
			WHERE id = %s 
	""";
	g.cur.execute(query, [license_id]);
	row = g.cur.fetchone();
	if not row:
		return None;
	return row["date_of_issue"];

"""
Checks for collision in amount unit names
"""
def check_for_collision_in_amount_unit(amount_unit):
	query = "SELECT name_ru FROM amount_units WHERE name_ru = %s";
	g.cur.execute(query, [amount_unit]);
	rows = g.cur.fetchall();
	return len(rows) > 0;

def check_for_collision_in_license(license, license_id):
	query = "SELECT * FROM licenses WHERE license = %s AND id <> %s";
	g.cur.execute(query, [license, license_id]);
	rows = g.cur.fetchall();
	return len(rows) > 0;

def check_for_collision_in_license_on_addition(license):
	query = "SELECT * FROM licenses WHERE license = %s";
	g.cur.execute(query, [license]);
	rows = g.cur.fetchall();
	return len(rows) > 0;

def check_for_collision_in_mineral(mineral):
	if not mineral or mineral == "":
		return True;
	query = "SELECT id FROM minerals WHERE name_ru LIKE %s";
	g.cur.execute(query, [mineral]);
	rows = g.cur.fetchall();
	return len(rows) > 0;

def check_for_collision_in_site(site):
	if not site or site == "":
		return True;
	query = "SELECT id FROM sites WHERE name_ru LIKE %s";
	g.cur.execute(query, [site]);
	rows = g.cur.fetchall();
	return len(rows) > 0;

def check_for_collision_in_deposit(deposit):
	if not deposit or deposit == "":
		return True;
	query = "SELECT id FROM deposits WHERE name_ru LIKE %s";
	g.cur.execute(query, [deposit]);
	rows = g.cur.fetchall();
	return len(rows) > 0;

def check_for_collision_in_depsoit_status(deposit_status):
	if not deposit_status or deposit_status == "":
		return True;
	query = "SELECT id FROM deposit_status WHERE name_ru LIKE %s";
	g.cur.execute(query, [deposit_status]);
	rows = g.cur.fetchall();
	return len(rows) > 0;

def check_for_collision_in_company(company):
	if not company or company == "":
		return True;
	query = "SELECT id FROM companies WHERE name_ru LIKE %s";
	g.cur.execute(query, [company]);
	rows = g.cur.fetchall();
	return len(rows) > 0;

"""
Gets resource id for the given amount unit
"""
def get_resource_id_for_amount_unit(amount_unit_id):
	query = """
		SELECT resource_id FROM amount_units
			WHERE id = %s
	""";
	g.cur.execute(query, [amount_unit_id]);
	row = g.cur.fetchone();
	if not row:
		return None;
	return row["resource_id"];

def get_resource_id_for_investment(investment_id):
	query = """
		SELECT resource_id FROM investments
			WHERE id = %s
	""";
	g.cur.execute(query, [investment_id]);
	row = g.cur.fetchone();
	if not row:
		return None;
	return row["resource_id"];

def get_resource_id_for_site(site_id):
	query = """
		SELECT resource_id FROM sites
			WHERE id = %s
	""";
	g.cur.execute(query, [site_id]);
	row = g.cur.fetchone();
	if not row:
		return None;
	return row["resource_id"];

def get_resource_id_for_deposit(deposit_id):
	query = """
		SELECT resource_id FROM deposits
			WHERE id = %s
	""";
	g.cur.execute(query, [deposit_id]);
	row = g.cur.fetchone();
	if not row:
		return None;
	return row["resource_id"];

def get_resource_id_for_deposit_site_type(deposit_site_type_id):
	query = """
		SELECT resource_id FROM deposits_sites_types
			WHERE id = %s
	""";
	g.cur.execute(query, [deposit_site_type_id]);
	row = g.cur.fetchone();
	if not row:
		return None;
	return row["resource_id"];

def get_resource_id_for_deposit_site(deposit_site_id):
	query = """
		SELECT resource_id FROM deposits_sites
			WHERE id = %s
	""";
	g.cur.execute(query, [deposit_site_id]);
	row = g.cur.fetchone();
	if not row:
		return None;
	return row["resource_id"];

def get_resource_id_for_deposit_status(deposit_status_id):
	query = """
		SELECT resource_id FROM deposit_status
			WHERE id = %s
	""";
	g.cur.execute(query, [deposit_status_id]);
	row = g.cur.fetchone();
	if not row:
		return None;
	return row["resource_id"];	

def get_resource_id_for_company(company_id):
	query = """
		SELECT resource_id FROM companies
			WHERE id = %s
	""";
	g.cur.execute(query, [company_id]);
	row = g.cur.fetchone();
	if not row:
		return None;
	return row["resource_id"];	

def get_resource_id_for_license(license_id):
	query = """
		SELECT resource_id FROM licenses
			WHERE id = %s
	""";
	g.cur.execute(query, [license_id]);
	row = g.cur.fetchone();
	if not row:
		return None;
	return row["resource_id"];	
"""
Gets resource id for the given mineral
"""
def get_resource_id_for_mineral(mineral_id):
	query = """
		SELECT resource_id FROM minerals
			WHERE id = %s
	""";
	g.cur.execute(query, [mineral_id]);
	row = g.cur.fetchone();
	if not row:
		return None;
	return row["resource_id"];

def get_resource_id_for_area(region_id, area_id):
	query = """
		SELECT resource_id FROM areas
			WHERE region_id = %s AND area_id = %s;
	""";
	g.cur.execute(query, [region_id, area_id]);
	row = g.cur.fetchone();
	if not row:
		return None;
	return row["resource_id"];

"""
Returns resource ID for given resource kind
"""
def get_resource_id_for_deposit_kind(deposit_kind_id):
	query = """
		SELECT resource_id FROM deposit_types
			WHERE kind_id = %s 
				AND group_id = 0
				AND type_id = 0
				AND subtype_id = 0
	""";
	g.cur.execute(query, [deposit_kind_id]);
	row = g.cur.fetchone();
	if not row:
		return None;
	return row["resource_id"];

"""
Returns resource ID for given resource kind and group
"""
def get_resource_id_for_deposit_group(deposit_kind_id, deposit_group_id):
	query = """
		SELECT resource_id FROM deposit_types
			WHERE kind_id = %s 
				AND group_id = %s
				AND type_id = 0
				AND subtype_id = 0
	""";
	g.cur.execute(query, [deposit_kind_id, deposit_group_id]);
	row = g.cur.fetchone();
	if not row:
		return None;
	return row["resource_id"];
"""
Returns resource ID for given resource kind, group and type
"""
def get_resource_id_for_deposit_type(
	deposit_kind_id, 
	deposit_group_id, 
	deposit_type_id):
	query = """
		SELECT resource_id FROM deposit_types
			WHERE kind_id = %s 
				AND group_id = %s
				AND type_id = %s
				AND subtype_id = 0
	""";
	g.cur.execute(query, [
		deposit_kind_id, 
		deposit_group_id, 
		deposit_type_id]);
	row = g.cur.fetchone();
	if not row:
		return None;
	return row["resource_id"];

"""
Returns resource ID for given resource kind, group and type
"""
def get_resource_id_for_deposit_subtype(
	deposit_kind_id, 
	deposit_group_id, 
	deposit_type_id,
	deposit_subtype_id):
	query = """
		SELECT resource_id FROM deposit_types
			WHERE kind_id = %s 
				AND group_id = %s
				AND type_id = %s
				AND subtype_id = %s
	""";
	g.cur.execute(query, [
		deposit_kind_id, 
		deposit_group_id, 
		deposit_type_id,
		deposit_subtype_id]);
	row = g.cur.fetchone();
	if not row:
		return None;
	return row["resource_id"];

"""
Gets current permissions
"""
def get_permissions(resource_id):
	query = """
		SELECT r.role FROM permissions p
			INNER JOIN roles r
				ON p.role_id = r.id
			INNER JOIN rights rt
				ON p.access_right_id = rt.id
			WHERE p.resource_id = %s 
			AND p.access_right_id = (SELECT id FROM rights WHERE access_right = 'read')
	""";
	g.cur.execute(query, [resource_id]);
	rows = g.cur.fetchall();
	permissions = [];
	permitted_roles = [];
	for row in rows:
		permitted_roles.append(row["role"]);
	query = "SELECT id, role FROM roles";
	g.cur.execute(query);
	rows = g.cur.fetchall();
	permissions = [];
	for row in rows:
		if row["role"] in permitted_roles:
			permissions.append({"id": row["id"], "role": row["role"], "granted": True});
		else:
			permissions.append({"id": row["id"], "role": row["role"], "granted": False});
	return permissions;
"""
Gets default permissions
"""
def get_default_permissions():
	query = "SELECT id, role FROM roles";
	g.cur.execute(query);
	rows = g.cur.fetchall();
	permissions = [];
	for row in rows:
		if row["role"] == "admin":
			permissions.append({"id": row["id"], "role": row["role"], "granted": True});
		else:
			permissions.append({"id": row["id"], "role": row["role"], "granted": False});
	return permissions;

"""
Gets all roles
"""
def get_roles():
	query = "SELECT id, role FROM roles";
	g.cur.execute(query);
	rows = g.cur.fetchall();
	roles = [];
	for row in rows:
		roles.append(row["role"]);
	return roles;

"""
Generates new UUID
"""
def get_uuid():
	query = "SELECT UUID() as id";
	g.cur.execute(query);
	row = g.cur.fetchone();
	return row["id"];

"""
Adds new resource
"""
def add_resource(uuid):
	query = "INSERT INTO resources(name) VALUES(%s)";
	g.cur.execute(query, [uuid]);
	g.db.commit();

"""
Gets resource id by UUID
"""
def get_resource_id(uuid):
	query = "SELECT id FROM resources WHERE name = %s";
	g.cur.execute(query, [uuid]);


"""
Adds read permission
"""
def add_read_permissions(roles, uuid):
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
"""
Updates read permissions
"""
def update_read_permissions(roles, resource_id):
	query = """
		DELETE FROM permissions 
			WHERE resource_id = %s
		"""
	g.cur.execute(query, [resource_id]);
	#g.db.commit();
	for role in roles:
		query = """
			INSERT INTO permissions(resource_id, role_id, access_right_id) 
			VALUES(
				%s,
				(SELECT id FROM roles WHERE role = %s),
				(SELECT id FROM rights WHERE access_right = "read")
			);"""
		g.cur.execute(query, [resource_id, role]);
	g.db.commit();

@app.route("/")
def default():
	return make_response(redirect("/login/"));

@app.route("/denied/")
def denied():
	return render_template("denied.html"); 

@app.route("/logout/")
def logout():
	response = make_response(redirect(url_for("login")));
	response.set_cookie("token", "", expires = 0);
	return response;

@app.route("/login/", methods=["GET", "POST"])
def login():
	if not ip_based_access_control(request.remote_addr, "192.168.0.0"):
		return redirect(url_for('denied'));
	if request.method == "POST":
		login_status = valid_login(request.form["username"], request.form["password"]);
		if login_status[0]:
			expire_date = datetime.datetime.utcnow() + \
				datetime.timedelta(seconds=config["MAX_SESSION_DURATION_IN_SECONDS"])
			random_token = Utils.token_hex();

			response = make_response(redirect(url_for('areas')));
			response.set_cookie(
				"token", 
				Token.encode(
					login_status[1], 
					login_status[2], 
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
		return redirect(url_for('denied'));
	if not is_valid_session(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if not is_admin(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	#role_id = Token.get_role_id(Token.decode(request.cookies.get("token", None)));
	if request.method == "GET":
		region_id = request.args.get("region_id", None);
		regions = get_regions();
		areas = [];
		if not region_id:
			if len(regions) > 0:
				region_id = regions[0]["region_id"];
		for region in regions:
			if region["region_id"] == int(region_id):
				regions.remove(region);
				regions.insert(0, region);
				break;
		query = """
				SELECT a.id, a.name_ru, a.area_id, a.region_id FROM areas a 
				WHERE a.region_id = %s AND a.area_id <> 0 ORDER BY a.name_ru ASC
				""";
		g.cur.execute(query, [int(region_id)]);
		rows = g.cur.fetchall();
		#print(g.cur._last_executed);
		for row in rows:
			areas.append({
				"id": row["id"], 
				"name": row["name_ru"], 
				"area_id": row["area_id"], 
				"region_id": row["region_id"]
				});
		return render_template("areas.html", 
			regions = regions, 
			areas = areas, 
			token = get_hash(request.cookies.get("token", None)));
	else:
		return redirect(url_for('login'));

@app.route("/delete_area/", methods=["GET"])
def delete_area():
	if not ip_based_access_control(request.remote_addr, "192.168.0.0"):
		return redirect(url_for('denied'));
	if not is_valid_session(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	"""
	If user is admin, then he/she can delete, create and modify all records already
	"""
	if not is_admin(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if not is_valid_hash(request.cookies.get("token", None), request.args.get("token", None)):
		return make_response(redirect(url_for("login")));
	#role_id = Token.get_role_id(Token.decode(request.cookies.get("token", None)));
	region_id = request.args.get("region_id", None);
	area_id = request.args.get("area_id", None);
	if not region_id or not area_id:
		return make_response(redirect(url_for("areas")));
	query = """
		DELETE FROM resources 
			WHERE id = 
				(SELECT resource_id FROM areas WHERE region_id = %s AND area_id = %s)
		""";
	g.cur.execute(query, [int(region_id), int(area_id)]);
	g.db.commit();
	return make_response(redirect(url_for("areas")));

@app.route("/add_area/", methods=["GET", "POST"])
def add_area():
	if not ip_based_access_control(request.remote_addr, "192.168.0.0"):
		return redirect(url_for('denied'));
	if not is_valid_session(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if not is_admin(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if request.method == "GET":
		return render_template("add_area.html", 
			regions = get_regions(), 
			permissions = get_default_permissions(), 
			error = None);
	elif request.method == "POST":
		region_id = request.form.get("region_id", None);
		area_name = request.form.get("area", None);
		if not region_id:
			return render_template("add_area.html", 
				regions = get_regions(), 
				permissions = get_default_permissions(), 
				error = u"Неверный код области");
		if not get_region(region_id):
			return render_template("add_area.html", 
				regions = get_regions(), 
				permissions = get_default_permissions(), 
				error = u"Неверный код области");
		#Make regular expression here
		if not area_name or area_name == "":
			return render_template("add_area.html", 
				regions = get_regions(), 
				permissions = get_default_permissions(), 
				error = u"Неверное наименование для района");		
		roles = get_roles();
		permitted_roles = get_roles_from_form(request.form, roles);
		uuid = get_uuid();
		add_resource(uuid);
		add_read_permissions(permitted_roles, uuid);
		query = """
			INSERT INTO areas(region_id, area_id, name_en, name_ru, name_uz, resource_id)
			VALUES(
				%s, 
				(SELECT MAX(a.area_id) + 1 FROM areas a WHERE region_id = %s),
				"", %s, "",
				(SELECT id FROM resources WHERE name = %s)
			)
		""";
		g.cur.execute(query, [region_id, region_id, area_name, uuid]);
		g.db.commit();
		return make_response(redirect(url_for("areas")));

@app.route("/edit_area/", methods=["GET", "POST"])
def edit_area():
	if not ip_based_access_control(request.remote_addr, "192.168.0.0"):
		return redirect(url_for('denied'));
	if not is_valid_session(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if not is_admin(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	#role_id = Token.get_role_id(Token.decode(request.cookies.get("token", None)));
	if request.method == "GET":
		region_id = request.args.get("region_id", None);
		area_id = request.args.get("area_id", None);
		if not get_area(region_id, area_id):
			return make_response(redirect(url_for("areas")));
		resource_id = get_resource_id_for_area(region_id, area_id);
		return render_template("edit_area.html", 
			region_id = region_id,
			area_id = area_id, 
			area = get_area(region_id, area_id),
			permissions = get_permissions(resource_id), 
			error = None);
	elif request.method == "POST":
		region_id = request.form.get("region_id", None);
		area_id = request.form.get("area_id", None);
		area_name = request.form.get("area", None);
		if not get_area(region_id, area_id):
			return make_response(redirect(url_for("areas")));
		resource_id = get_resource_id_for_area(region_id, area_id);
		#Make regular expression here
		if not area_name or area_name == "":
			return render_template("edit_area.html", 
				region_id = region_id,
				area_id = area_id, 
				area = get_area(region_id, area_id),
				permissions = get_permissions(resource_id), 
				error = u"Неверное наименование для района");
		roles = get_roles();
		permitted_roles = get_roles_from_form(request.form, roles);
		update_read_permissions(permitted_roles, resource_id);
		query = """
			UPDATE areas SET name_ru = %s
				WHERE region_id = %s AND area_id = %s
		""";
		g.cur.execute(query, [area_name, region_id, area_id]);
		g.db.commit();
		return make_response(redirect(url_for("areas")));

@app.route("/amount_units/", methods=["GET", "POST"])
def amount_units():
	if not ip_based_access_control(request.remote_addr, "192.168.0.0"):
		return redirect(url_for('denied'));
	if not is_valid_session(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if not is_admin(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if request.method == "GET":
		query = "SELECT id, name_ru FROM amount_units";
		g.cur.execute(query);
		rows = g.cur.fetchall();
		amount_units = [];
		for row in rows:
			amount_units.append({
				"id": row["id"], 
				"name": row["name_ru"]
				});
		return render_template("amount_units.html", 
			amount_units = amount_units, 
			token = get_hash(request.cookies.get("token", None)));
	else:
		return redirect(url_for('login'));

@app.route("/delete_amount_unit/", methods=["GET", "POST"])
def delete_amount_units():
	if not ip_based_access_control(request.remote_addr, "192.168.0.0"):
		return redirect(url_for('denied'));
	if not is_valid_session(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if not is_admin(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if not is_valid_hash(request.cookies.get("token", None), request.args.get("token", None)):
		return make_response(redirect(url_for("login")));
	if request.method == "GET":
		amount_unit_id = request.args.get("amount_unit_id", None);
		if not amount_unit_id:
			return make_response(redirect(url_for("amount_units")));
		query = """
			DELETE FROM resources 
				WHERE id = 
					(SELECT resource_id FROM amount_units WHERE id = %s)
		""";
		g.cur.execute(query, [int(amount_unit_id)]);
		rows = g.db.commit();
		return make_response(redirect(url_for("amount_units")));
	else:
		return redirect(url_for('login'));

@app.route("/add_amount_unit/", methods=["GET", "POST"])
def add_amount_unit():
	if not ip_based_access_control(request.remote_addr, "192.168.0.0"):
		return redirect(url_for('denied'));
	if not is_valid_session(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if not is_admin(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if request.method == "GET":
		return render_template("add_amount_unit.html", 
			permissions = get_default_permissions(), 
			error = None);
	elif request.method == "POST":
		amount_unit = request.form.get("amount_unit", None);
		#Make regular expression here
		if not amount_unit or amount_unit == "":
			return render_template("add_amount_unit.html", 
				permissions = get_default_permissions(), 
				error = u"Неверное наименование для единицы измерения");		
		"""if check_for_collision_in_names(amount_unit):
			return render_template("add_amount_unit.html", 
				permissions = get_default_permissions(), 
				error = u"Данная единица измерения уже существует в базе");
		"""
		roles = get_roles();
		permitted_roles = get_roles_from_form(request.form, roles);
		uuid = get_uuid();
		add_resource(uuid);
		add_read_permissions(permitted_roles, uuid);
		query = """
			INSERT INTO amount_units(name_en, name_ru, name_uz, resource_id)
			VALUES(
				"", %s, "",
				(SELECT id FROM resources WHERE name = %s)
			)
		""";
		g.cur.execute(query, [amount_unit, uuid]);
		g.db.commit();
		return make_response(redirect(url_for("amount_units")));

@app.route("/edit_amount_unit/", methods=["GET", "POST"])
def edit_amount_unit():
	if not ip_based_access_control(request.remote_addr, "192.168.0.0"):
		return redirect(url_for('denied'));
	if not is_valid_session(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if not is_admin(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if request.method == "GET":
		amount_unit_id = request.args.get("amount_unit_id", None);
		#if not get_amount_unit(amount_unit_id):
		#	return make_response(redirect(url_for("amount_units")));
		resource_id = get_resource_id_for_amount_unit(amount_unit_id);
		return render_template("edit_amount_unit.html", 
			amount_unit_id = amount_unit_id,
			amount_unit = get_amount_unit(amount_unit_id),
			permissions = get_permissions(resource_id), 
			error = None);
	elif request.method == "POST":
		amount_unit_id = request.form.get("amount_unit_id", None);
		amount_unit = request.form.get("amount_unit", None);
		#if not get_amount_unit(amount_unit_id):
		#	return make_response(redirect(url_for("amount_units")));
		resource_id = get_resource_id_for_amount_unit(amount_unit_id);
		#Make regular expression here
		if not amount_unit or amount_unit == "":
			return render_template("edit_amount_unit.html", 
				amount_unit_id = amount_unit_id,
				amount_unit = get_amount_unit(amount_unit_id),
				permissions = get_permissions(resource_id),
				error = u"Неверное наименование для единицы измерения");
		"""
		if check_for_collision_in_names(amount_unit):
			return render_template("edit_amount_unit.html", 
				amount_unit_id = amount_unit_id,
				amount_unit = get_amount_unit(amount_unit_id),
				permissions = get_permissions(resource_id),
				error = u"Данная единица измерения уже существует в базе");
		"""
		roles = get_roles();
		permitted_roles = get_roles_from_form(request.form, roles);
		update_read_permissions(permitted_roles, resource_id);
		query = """
			UPDATE amount_units SET name_ru = %s
				WHERE id = %s
		""";
		g.cur.execute(query, [amount_unit, amount_unit_id]);
		g.db.commit();
		return make_response(redirect(url_for("amount_units")));

@app.route("/deposit_kinds/", methods=["GET", "POST"])
def deposit_kinds():
	if not ip_based_access_control(request.remote_addr, "192.168.0.0"):
		return redirect(url_for('denied'));
	if not is_valid_session(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if not is_admin(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if request.method == "GET":
		query = """SELECT kind_id, name_ru 
			FROM deposit_types WHERE kind_id <> 0
			AND group_id = 0 
			AND type_id = 0
			AND subtype_id = 0
			""";
		g.cur.execute(query);
		rows = g.cur.fetchall();
		deposit_kinds = [];
		for row in rows:
			deposit_kinds.append({
				"kind_id": row["kind_id"], 
				"name": row["name_ru"]
				});
		return render_template("deposit_kinds.html", 
			deposit_kinds = deposit_kinds,
			token = get_hash(request.cookies.get("token", None)));
	else:
		return redirect(url_for('login'));

@app.route("/delete_deposit_kind/", methods=["GET", "POST"])
def delete_deposit_kind():
	if not ip_based_access_control(request.remote_addr, "192.168.0.0"):
		return redirect(url_for('denied'));
	if not is_valid_session(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if not is_admin(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if not is_valid_hash(request.cookies.get("token", None), request.args.get("token", None)):
		return make_response(redirect(url_for("login")));
	if request.method == "GET":
		deposit_kind_id = request.args.get("kind_id", None);
		if not deposit_kind_id:
			return make_response(redirect(url_for("deposit_kinds")));
		query = """
			DELETE FROM resources 
				WHERE id IN 
					(SELECT resource_id FROM deposit_types WHERE kind_id = %s)
		""";
		g.cur.execute(query, [int(deposit_kind_id)]);
		rows = g.db.commit();
		return make_response(redirect(url_for("deposit_kinds")));
	else:
		return redirect(url_for('login'));

@app.route("/edit_deposit_kind/", methods=["GET", "POST"])
def edit_deposit_kind():
	if not ip_based_access_control(request.remote_addr, "192.168.0.0"):
		return redirect(url_for('denied'));
	if not is_valid_session(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if not is_admin(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if request.method == "GET":
		deposit_kind_id = request.args.get("kind_id", None);
		if not get_deposit_kind(deposit_kind_id):
			return make_response(redirect(url_for("deposit_kinds")));
		resource_id = get_resource_id_for_deposit_kind(deposit_kind_id);
		if not resource_id:
			return make_response(redirect(url_for("deposit_kinds")));
		return render_template("edit_deposit_kind.html", 
			deposit_kind_id = deposit_kind_id,
			deposit_kind = get_deposit_kind(deposit_kind_id),
			permissions = get_permissions(resource_id), 
			error = None);
	else:
		deposit_kind_id = request.form.get("deposit_kind_id", None);
		deposit_kind = request.form.get("deposit_kind", None);
		if not get_deposit_kind(deposit_kind_id):
			return make_response(redirect(url_for("deposit_kinds")));
		resource_id = get_resource_id_for_deposit_kind(deposit_kind_id);
		#Make regular expression here
		if not deposit_kind or deposit_kind == "":
			return render_template("edit_deposit_kind.html", 
				deposit_kind_id = deposit_kind_id,
				deposit_kind = get_deposit_kind(deposit_kind_id),
				permissions = get_permissions(resource_id),
				error = u"Неверное название вида");
		roles = get_roles();
		permitted_roles = get_roles_from_form(request.form, roles);
		update_read_permissions(permitted_roles, resource_id);
		query = """
			UPDATE deposit_types SET name_ru = %s
				WHERE kind_id = %s
					AND group_id = 0
					AND type_id = 0
					AND subtype_id = 0
		""";
		g.cur.execute(query, [deposit_kind, deposit_kind_id]);
		g.db.commit();
		return make_response(redirect(url_for("deposit_kinds")));

@app.route("/add_deposit_kind/", methods=["GET", "POST"])
def add_deposit_kind():
	if not ip_based_access_control(request.remote_addr, "192.168.0.0"):
		return redirect(url_for('denied'));
	if not is_valid_session(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if not is_admin(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if request.method == "GET":
		return render_template("add_deposit_kind.html", 
			permissions = get_default_permissions(), 
			error = None);
	else:
		deposit_kind = request.form.get("deposit_kind", None);
		#Make regular expression here
		if not deposit_kind or deposit_kind == "":
			return render_template("add_deposit_kind.html", 
				permissions = get_default_permissions(), 
				error = u"Неверное наименование для вида");		
		roles = get_roles();
		permitted_roles = get_roles_from_form(request.form, roles);
		uuid = get_uuid();
		add_resource(uuid);
		add_read_permissions(permitted_roles, uuid);
		query = """
			INSERT INTO deposit_types(
				name_en, 
				name_ru, 
				name_uz, 
				kind_id, 
				group_id, 
				type_id, 
				subtype_id, 
				resource_id)
			VALUES(
				"", %s, "", 
				(SELECT IF(MAX(dt.kind_id) IS NULL, 1, MAX(dt.kind_id) + 1) 
					FROM deposit_types dt 
					WHERE dt.kind_id <> 0 
						AND dt.group_id = 0 
						AND dt.type_id = 0 
						AND dt.subtype_id = 0),
				0, 0, 0,
				(SELECT id FROM resources WHERE name = %s)
			)
		""";
		g.cur.execute(query, [deposit_kind, uuid]);
		g.db.commit();
		return make_response(redirect(url_for("deposit_kinds")));

@app.route("/deposit_groups_ajax/", methods=["GET"])
def deposit_groups_ajax():
	if not ip_based_access_control(request.remote_addr, "192.168.0.0"):
		return jsonify([]);
	if not is_valid_session(request.cookies.get("token", None)):
		return jsonify([]);
	if not is_admin(request.cookies.get("token", None)):
		return jsonify([]);
	deposit_kind_id = request.args.get("deposit_kind_id", None);
	if not deposit_kind_id:
		return jsonify([]);
	query = """
			SELECT dt.id, dt.kind_id, dt.group_id, dt.name_ru FROM deposit_types dt 
			WHERE dt.kind_id = %s AND dt.group_id <> 0 
			AND dt.type_id = 0 AND dt.subtype_id = 0
	""";
	deposit_groups = [];
	g.cur.execute(query, [int(deposit_kind_id)]);
	rows = g.cur.fetchall();
	for row in rows:
		deposit_groups.append({
			"id": row["id"], 
			"name": row["name_ru"], 
			"kind_id": row["kind_id"], 
			"group_id": row["group_id"]
		});
	return jsonify(deposit_groups);

@app.route("/deposit_types_ajax/", methods=["GET"])
def deposit_types_ajax():
	if not ip_based_access_control(request.remote_addr, "192.168.0.0"):
		return jsonify([]);
	if not is_valid_session(request.cookies.get("token", None)):
		return jsonify([]);
	if not is_admin(request.cookies.get("token", None)):
		return jsonify([]);
	deposit_kind_id = request.args.get("deposit_kind_id", None);
	if not deposit_kind_id:
		return jsonify([]);
	deposit_group_id = request.args.get("deposit_group_id", None);
	if not deposit_group_id:
		return jsonify([]);
	query = """
			SELECT dt.id, dt.kind_id, dt.group_id, dt.type_id, dt.name_ru FROM deposit_types dt 
			WHERE dt.kind_id = %s AND dt.group_id = %s 
			AND dt.type_id <> 0 AND dt.subtype_id = 0
	""";
	deposit_types = [];
	g.cur.execute(query, [int(deposit_kind_id), int(deposit_group_id)]);
	rows = g.cur.fetchall();
	for row in rows:
		deposit_types.append({
			"id": row["id"], 
			"name": row["name_ru"], 
			"kind_id": row["kind_id"], 
			"group_id": row["group_id"],
			"type_id": row["type_id"]
		});
	return jsonify(deposit_types);

@app.route("/deposit_subtypes_ajax/", methods=["GET"])
def deposit_subtypes_ajax():
	if not ip_based_access_control(request.remote_addr, "192.168.0.0"):
		return jsonify([]);
	if not is_valid_session(request.cookies.get("token", None)):
		return jsonify([]);
	if not is_admin(request.cookies.get("token", None)):
		return jsonify([]);
	deposit_kind_id = request.args.get("deposit_kind_id", None);
	if not deposit_kind_id:
		return jsonify([]);
	deposit_group_id = request.args.get("deposit_group_id", None);
	if not deposit_group_id:
		return jsonify([]);
	deposit_type_id = request.args.get("deposit_type_id", None);
	if not deposit_type_id:
		return jsonify([]);
	query = """
			SELECT dt.id, dt.kind_id, dt.group_id, dt.type_id, dt.subtype_id, dt.name_ru FROM deposit_types dt 
			WHERE dt.kind_id = %s AND dt.group_id = %s 
			AND dt.type_id = %s AND dt.subtype_id <> 0
	""";
	deposit_subtypes = [];
	g.cur.execute(query, [int(deposit_kind_id), int(deposit_group_id), int(deposit_type_id)]);
	rows = g.cur.fetchall();
	for row in rows:
		deposit_subtypes.append({
			"id": row["id"], 
			"name": row["name_ru"], 
			"kind_id": row["kind_id"], 
			"group_id": row["group_id"],
			"type_id": row["type_id"],
			"subtype_id": row["subtype_id"]
		});
	return jsonify(deposit_subtypes);

@app.route("/deposit_groups/", methods=["GET"])
def deposit_groups():
	if not ip_based_access_control(request.remote_addr, "192.168.0.0"):
		return redirect(url_for('denied'));
	if not is_valid_session(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if not is_admin(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if request.method == "GET":
		deposit_kind_id = request.args.get("deposit_kind_id", None);
		deposit_kinds = get_deposit_kinds();
		deposit_groups = [];
		if not deposit_kind_id:
			if len(deposit_kinds) > 0:
				deposit_kind_id = deposit_kinds[0]["kind_id"];
		for deposit_kind in deposit_kinds:
			if deposit_kind["kind_id"] == int(deposit_kind_id):
				deposit_kinds.remove(deposit_kind);
				deposit_kinds.insert(0, deposit_kind);
				break;
		query = """
				SELECT dt.id, dt.kind_id, dt.group_id, dt.name_ru FROM deposit_types dt 
				WHERE dt.kind_id = %s AND dt.group_id <> 0 
				AND dt.type_id = 0 AND dt.subtype_id = 0
				""";
		if not deposit_kind_id:
			return make_response(render_template("deposit_groups.html", 
				deposit_kinds = [], 
				deposit_groups = [],
				token = get_hash(request.cookies.get("token", None))));
		g.cur.execute(query, [int(deposit_kind_id)]);
		rows = g.cur.fetchall();
		for row in rows:
			deposit_groups.append({
				"id": row["id"], 
				"name": row["name_ru"], 
				"kind_id": row["kind_id"], 
				"group_id": row["group_id"]
				});
		return make_response(render_template("deposit_groups.html", 
			deposit_kinds = deposit_kinds, 
			deposit_groups = deposit_groups,
			token = get_hash(request.cookies.get("token", None))));

@app.route("/delete_deposit_group/", methods=["GET"])
def delete_deposit_group():
	if not ip_based_access_control(request.remote_addr, "192.168.0.0"):
		return redirect(url_for('denied'));
	if not is_valid_session(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if not is_admin(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if not is_valid_hash(request.cookies.get("token", None), request.args.get("token", None)):
		return make_response(redirect(url_for("login")));
	if request.method == "GET":
		deposit_kind_id = request.args.get("kind_id", None);
		deposit_group_id = request.args.get("group_id", None);
		if not deposit_kind_id:
			return make_response(redirect(url_for("deposit_groups")));
		if not deposit_group_id:
			return make_response(redirect(url_for("deposit_groups")));
		query = """
			DELETE FROM resources 
				WHERE id IN 
					(SELECT resource_id FROM deposit_types WHERE kind_id = %s AND group_id = %s)
		""";
		g.cur.execute(query, [int(deposit_kind_id), int(deposit_group_id)]);
		rows = g.db.commit();
		return make_response(redirect(url_for("deposit_groups")));
	else:
		return make_response(redirect(url_for("deposit_groups")));	

@app.route("/edit_deposit_group/", methods=["GET", "POST"])
def edit_deposit_group():
	if not ip_based_access_control(request.remote_addr, "192.168.0.0"):
		return redirect(url_for('denied'));
	if not is_valid_session(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if not is_admin(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if request.method == "GET":
		deposit_kind_id = request.args.get("kind_id", None);
		deposit_group_id = request.args.get("group_id", None);
		if not get_deposit_kind(deposit_kind_id):
			return make_response(redirect(url_for("deposit_groups")));
		if not get_deposit_group(deposit_kind_id, deposit_group_id):
			return make_response(redirect(url_for("deposit_groups")));
		resource_id = get_resource_id_for_deposit_group(deposit_kind_id, deposit_group_id);
		if not resource_id:
			return make_response(redirect(url_for("deposit_groups")));
		return render_template("edit_deposit_group.html", 
			deposit_kind_id = deposit_kind_id,
			deposit_group_id = deposit_group_id,
			deposit_group = get_deposit_group(deposit_kind_id, deposit_group_id),
			permissions = get_permissions(resource_id), 
			error = None);
	else:
		deposit_kind_id = request.form.get("deposit_kind_id", None);
		deposit_group_id = request.form.get("deposit_group_id", None);
		deposit_group = request.form.get("deposit_group", None);
		if not get_deposit_kind(deposit_kind_id):
			return make_response(redirect(url_for("deposit_groups")));
		if not get_deposit_group(deposit_kind_id, deposit_group_id):
			return make_response(redirect(url_for("deposit_groups")));
		resource_id = get_resource_id_for_deposit_group(deposit_kind_id, deposit_group_id);
		if not deposit_group or deposit_group == "":
			return render_template("edit_deposit_group.html", 
				deposit_kind_id = deposit_kind_id,
				deposit_group_id = deposit_group_id,
				deposit_kind = get_deposit_group(deposit_kind_id, deposit_group_id),
				permissions = get_permissions(resource_id),
				error = u"Неверное название для группы");
		roles = get_roles();
		permitted_roles = get_roles_from_form(request.form, roles);
		update_read_permissions(permitted_roles, resource_id);
		query = """
			UPDATE deposit_types SET name_ru = %s
				WHERE kind_id = %s
					AND group_id = %s
					AND type_id = 0
					AND subtype_id = 0
		""";
		g.cur.execute(query, [deposit_group, deposit_kind_id, deposit_group_id]);
		g.db.commit();
		return make_response(redirect(url_for("deposit_groups")));

@app.route("/add_deposit_group/", methods=["GET", "POST"])
def add_deposit_group():
	if not ip_based_access_control(request.remote_addr, "192.168.0.0"):
		return redirect(url_for('denied'));
	if not is_valid_session(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if not is_admin(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if request.method == "GET":
		return render_template("add_deposit_group.html", 
			deposit_kinds = get_deposit_kinds(), 
			permissions = get_default_permissions(), 
			error = None);
	elif request.method == "POST":
		kind_id = request.form.get("deposit_kind_id", None);
		deposit_group = request.form.get("deposit_group", None);
		if not kind_id:
			return render_template("add_deposit_group.html", 
				deposit_kinds = get_deposit_kinds(),
				permissions = get_default_permissions(), 
				error = "Неверный вид");
		if not get_deposit_kind(kind_id):
			return render_template("add_deposit_group.html", 
				deposit_kinds = get_deposit_kinds(),
				permissions = get_default_permissions(), 
				error = "Неверный вид");
		#Make regular expression here
		if not deposit_group or deposit_group == "":
			return render_template("add_deposit_group.html", 
				deposit_kinds = get_deposit_kinds(),
				permissions = get_default_permissions(), 
				error = u"Неверное наименование для группы");
		roles = get_roles();
		permitted_roles = get_roles_from_form(request.form, roles);
		uuid = get_uuid();
		add_resource(uuid);
		add_read_permissions(permitted_roles, uuid);
		query = """
			INSERT INTO deposit_types(kind_id, group_id, type_id, subtype_id, name_en, name_ru, name_uz, resource_id)
			VALUES(
				%s, 
				(SELECT MAX(dt.group_id) + 1 FROM deposit_types dt WHERE dt.kind_id = %s AND dt.type_id = 0 AND dt.subtype_id = 0),
				0, 0,
				"", %s, "",
				(SELECT id FROM resources WHERE name = %s)
			)
		""";
		g.cur.execute(query, [kind_id, kind_id, deposit_group, uuid]);
		g.db.commit();
		return make_response(redirect(url_for("deposit_groups")));

@app.route("/deposit_types/", methods=["GET"])
def deposit_types():
	if not ip_based_access_control(request.remote_addr, "192.168.0.0"):
		return redirect(url_for('denied'));
	if not is_valid_session(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if not is_admin(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if request.method == "GET":
		deposit_kind_id = request.args.get("deposit_kind_id", None);
		deposit_group_id = request.args.get("deposit_group_id", None);
		deposit_kinds = get_deposit_kinds();
		if not deposit_kind_id:
			if len(deposit_kinds) > 0:
				deposit_kind_id = deposit_kinds[0]["kind_id"];
			else:
				deposit_kind_id = -1;
		deposit_groups = get_deposit_groups(deposit_kind_id);
		for deposit_kind in deposit_kinds:
			if deposit_kind["kind_id"] == int(deposit_kind_id):
				deposit_kinds.remove(deposit_kind);
				deposit_kinds.insert(0, deposit_kind);
				break;

		if not deposit_group_id or not get_deposit_group(deposit_kind_id, deposit_group_id):
			if len(deposit_groups) > 0:
				deposit_group_id = deposit_groups[0]["group_id"];
			else:
				deposit_group_id = -1;

		for deposit_group in deposit_groups:
			if deposit_group["group_id"] == int(deposit_group_id):
				deposit_groups.remove(deposit_group);
				deposit_groups.insert(0, deposit_group);
				break;
		query = """
				SELECT dt.id, dt.kind_id, dt.group_id, dt.type_id, dt.name_ru FROM deposit_types dt 
				WHERE dt.kind_id = %s AND dt.group_id = %s
				AND dt.type_id <> 0 AND dt.subtype_id = 0
				""";
		g.cur.execute(query, [int(deposit_kind_id), int(deposit_group_id)]);
		rows = g.cur.fetchall();
		deposit_types = [];

		for row in rows:
			deposit_types.append({
				"id": row["id"], 
				"name": row["name_ru"], 
				"kind_id": row["kind_id"], 
				"group_id": row["group_id"],
				"type_id": row["type_id"]
				});
		return make_response(render_template("deposit_types.html", 
			deposit_kinds = deposit_kinds, 
			deposit_groups = deposit_groups,
			deposit_types = deposit_types,
			token = get_hash(request.cookies.get("token", None))
			));

@app.route("/delete_deposit_type/", methods=["GET", "POST"])
def delete_deposit_type():
	if not ip_based_access_control(request.remote_addr, "192.168.0.0"):
		return redirect(url_for('denied'));
	if not is_valid_session(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if not is_admin(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if not is_valid_hash(request.cookies.get("token", None), request.args.get("token", None)):
		return make_response(redirect(url_for("login")));
	if request.method == "GET":
		deposit_kind_id = request.args.get("kind_id", None);
		deposit_group_id = request.args.get("group_id", None);
		deposit_type_id = request.args.get("type_id", None);
		if not deposit_kind_id:
			return make_response(redirect(url_for("deposit_types")));
		if not deposit_group_id:
			return make_response(redirect(url_for("deposit_types")));
		if not deposit_type_id:
			return make_response(redirect(url_for("deposit_types")));
		query = """
			DELETE FROM resources 
				WHERE id IN 
					(SELECT resource_id 
						FROM deposit_types 
						WHERE kind_id = %s 
							AND group_id = %s
							AND type_id = %s)
		""";
		g.cur.execute(query, [int(deposit_kind_id), int(deposit_group_id), int(deposit_type_id)]);
		rows = g.db.commit();
		return make_response(redirect(url_for("deposit_types")));
	else:
		return redirect(url_for('login'));

@app.route("/edit_deposit_type/", methods=["GET", "POST"])
def edit_deposit_type():
	if not ip_based_access_control(request.remote_addr, "192.168.0.0"):
		return redirect(url_for('denied'));
	if not is_valid_session(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if not is_admin(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if request.method == "GET":
		deposit_kind_id = request.args.get("kind_id", None);
		deposit_group_id = request.args.get("group_id", None);
		deposit_type_id = request.args.get("type_id", None);
		if not get_deposit_kind(deposit_kind_id):
			return make_response(redirect(url_for("deposit_types")));
		if not get_deposit_group(deposit_kind_id, deposit_group_id):
			return make_response(redirect(url_for("deposit_types")));
		if not get_deposit_type(deposit_kind_id, deposit_group_id, deposit_type_id):
			return make_response(redirect(url_for("deposit_types")));
		resource_id = get_resource_id_for_deposit_type(deposit_kind_id, 
			deposit_group_id, 
			deposit_type_id);
		if not resource_id:
			return make_response(redirect(url_for("deposit_types")));
		return render_template("edit_deposit_type.html", 
			deposit_kind_id = deposit_kind_id,
			deposit_group_id = deposit_group_id,
			deposit_type_id = deposit_type_id,
			deposit_type = get_deposit_type(deposit_kind_id, deposit_group_id, deposit_type_id),
			permissions = get_permissions(resource_id), 
			error = None);
	else:
		deposit_kind_id = request.form.get("deposit_kind_id", None);
		deposit_group_id = request.form.get("deposit_group_id", None);
		deposit_type_id = request.form.get("deposit_type_id", None);
		deposit_type = request.form.get("deposit_type", None);
		if not get_deposit_kind(deposit_kind_id):
			return make_response(redirect(url_for("deposit_types")));
		if not get_deposit_group(deposit_kind_id, deposit_group_id):
			return make_response(redirect(url_for("deposit_types")));
		if not get_deposit_type(deposit_kind_id, deposit_group_id, deposit_type_id):
			return make_response(redirect(url_for("deposit_types")));
		resource_id = get_resource_id_for_deposit_type(deposit_kind_id, 
			deposit_group_id, 
			deposit_type_id);
		#Make regular expression here
		if not deposit_type or deposit_type == "":
			return render_template("edit_deposit_type.html", 
				deposit_kind_id = deposit_kind_id,
				deposit_group_id = deposit_group_id,
				deposit_type_id = deposit_type_id,
				deposit_type = get_deposit_type(deposit_kind_id, deposit_group_id, deposit_type_id),
				permissions = get_permissions(resource_id), 
				error = "Неверное наименование для типа");
		roles = get_roles();
		permitted_roles = get_roles_from_form(request.form, roles);
		update_read_permissions(permitted_roles, resource_id);
		query = """
			UPDATE deposit_types SET name_ru = %s
				WHERE kind_id = %s
					AND group_id = %s
					AND type_id = %s
					AND subtype_id = 0
		""";
		g.cur.execute(query, [deposit_type, deposit_kind_id, deposit_group_id, deposit_type_id]);
		g.db.commit();
		return make_response(redirect(url_for("deposit_types")));

@app.route("/add_deposit_type/", methods=["GET", "POST"])
def add_deposit_type():
	if not ip_based_access_control(request.remote_addr, "192.168.0.0"):
		return redirect(url_for('denied'));
	if not is_valid_session(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if not is_admin(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if request.method == "GET":
		deposit_kinds = get_deposit_kinds();
		if len(deposit_kinds) == 0:
			return make_response(redirect(url_for("deposit_kinds")));
		deposit_kind_id = deposit_kinds[0]["kind_id"];
		return render_template("add_deposit_type.html", 
			deposit_kinds = get_deposit_kinds(), 
			deposit_groups = get_deposit_groups(deposit_kind_id),
			permissions = get_default_permissions(), 
			error = None);
	elif request.method == "POST":
		deposit_kind_id = request.form.get("deposit_kind_id", None);
		deposit_group_id = request.form.get("deposit_group_id", None);
		deposit_type = request.form.get("deposit_type", None);
		if not deposit_kind_id:
			deposit_kinds = get_deposit_kinds();
			if len(deposit_kinds) == 0:
				return make_response(redirect(url_for("deposit_kinds")));
			deposit_kind_id = deposit_kinds[0]["kind_id"];
			return render_template("add_deposit_type.html", 
				deposit_kinds = deposit_kinds, 
				deposit_groups = get_deposit_groups(deposit_kind_id),
				permissions = get_default_permissions(), 
				error = u"Неверный вид");
		if not get_deposit_kind(deposit_kind_id):
			deposit_kinds = get_deposit_kinds();
			if len(deposit_kinds) == 0:
				return make_response(redirect(url_for("deposit_kinds")));
			deposit_kind_id = deposit_kinds[0]["kind_id"];
			return render_template("add_deposit_type.html", 
				deposit_kinds = deposit_kinds, 
				deposit_groups = get_deposit_groups(deposit_kind_id),
				permissions = get_default_permissions(), 
				error = u"Неверный вид");
		if not deposit_group_id:
			deposit_groups = get_deposit_groups(deposit_kind_id);
			deposit_kinds = get_deposit_kinds();
			for deposit_kind in deposit_kinds:
				if deposit_kind["kind_id"] == int(deposit_kind_id):
					deposit_kinds.remove(deposit_kind);
					deposit_kinds.insert(0, deposit_kind);
			if len(deposit_groups) == 0:
				return render_template("add_deposit_type.html", 
					deposit_kinds = deposit_kinds, 
					deposit_groups = [],
					permissions = get_default_permissions(), 
					error = u"Неверная группа");
			deposit_group_id = deposit_groups[0]["group_id"];			
			return render_template("add_deposit_type.html", 
				deposit_kinds = deposit_kinds, 
				deposit_groups = get_deposit_groups(deposit_kind_id),
				permissions = get_default_permissions(), 
				error = u"Неверная группа");
		if not get_deposit_group(deposit_kind_id, deposit_group_id):
			deposit_kinds = get_deposit_kinds();
			deposit_kind_id = deposit_kinds[0]["kind_id"];
			deposit_groups = get_deposit_groups(deposit_kind_id);
			if len(deposit_groups) == 0:
				return render_template("add_deposit_type.html", 
					deposit_kinds = deposit_kinds, 
					deposit_groups = [],
					permissions = get_default_permissions(), 
					error = u"Неверная группа");
			return render_template("add_deposit_type.html", 
				deposit_kinds = deposit_kinds, 
				deposit_groups = deposit_groups,
				permissions = get_default_permissions(), 
				error = u"Неверная группа");
		#Make regular expression here
		if not deposit_type or deposit_type == "":
			deposit_kinds = get_deposit_kinds();
			for deposit_kind in deposit_kinds:
				if deposit_kind["kind_id"] == int(deposit_kind_id):
					deposit_kinds.remove(deposit_kind);
					deposit_kinds.insert(0, deposit_kind);
			deposit_groups = get_deposit_groups(deposit_kind_id);
			for deposit_group in deposit_groups:
				if deposit_group["group_id"] == int(deposit_group_id):
					deposit_groups.remove(deposit_group);
					deposit_groups.insert(0, deposit_group);
			return render_template("add_deposit_type.html", 
				deposit_kinds = deposit_kinds, 
				deposit_groups = deposit_groups,
				permissions = get_default_permissions(), 
				error = u"Неверное наименование для типа");
		roles = get_roles();
		permitted_roles = get_roles_from_form(request.form, roles);
		uuid = get_uuid();
		add_resource(uuid);
		add_read_permissions(permitted_roles, uuid);
		query = """
			INSERT INTO deposit_types(
				kind_id, 
				group_id, 
				type_id, 
				subtype_id, 
				name_en, 
				name_ru, 
				name_uz, 
				resource_id)
			VALUES(
				%s, 
				%s,
				(SELECT MAX(dt.type_id) + 1 
					FROM deposit_types dt 
						WHERE dt.kind_id = %s 
							AND dt.group_id = %s 
							AND dt.subtype_id = 0),
				0,
				"", %s, "",
				(SELECT id FROM resources WHERE name = %s)
			)
		""";
		g.cur.execute(query, [int(deposit_kind_id), 
			int(deposit_group_id), 
			int(deposit_kind_id), 
			int(deposit_group_id), 
			deposit_type, uuid]);
		g.db.commit();
		return make_response(redirect(url_for("deposit_types")));

@app.route("/deposit_subtypes/", methods=["GET"])
def deposit_subtypes():
	if not ip_based_access_control(request.remote_addr, "192.168.0.0"):
		return redirect(url_for('denied'));
	if not is_valid_session(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if not is_admin(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if request.method == "GET":
		deposit_kind_id = request.args.get("deposit_kind_id", None);
		deposit_group_id = request.args.get("deposit_group_id", None);
		deposit_type_id = request.args.get("deposit_type_id", None);
		deposit_kinds = get_deposit_kinds();
		if not deposit_kind_id:
			if len(deposit_kinds) > 0:
				deposit_kind_id = deposit_kinds[0]["kind_id"];
			else:
				deposit_kind_id = -1;
		for deposit_kind in deposit_kinds:
			if deposit_kind["kind_id"] == int(deposit_kind_id):
				deposit_kinds.remove(deposit_kind);
				deposit_kinds.insert(0, deposit_kind);
				break;
		deposit_groups = get_deposit_groups(deposit_kind_id);
		if not deposit_group_id or not get_deposit_group(deposit_kind_id, deposit_group_id):
			if len(deposit_groups) > 0:
				deposit_group_id = deposit_groups[0]["group_id"];
			else:
				deposit_group_id = -1;
		for deposit_group in deposit_groups:
			if deposit_group["group_id"] == int(deposit_group_id):
				deposit_groups.remove(deposit_group);
				deposit_groups.insert(0, deposit_group);
				break;
		deposit_types = get_deposit_types(deposit_kind_id, deposit_group_id);
		if not deposit_type_id or not get_deposit_type(deposit_kind_id, deposit_group_id, deposit_type_id):
			if len(deposit_types) > 0:
				deposit_type_id = deposit_types[0]["type_id"];
			else:
				deposit_type_id = -1;
		for deposit_type in deposit_types:
			if deposit_type["type_id"] == int(deposit_type_id):
				deposit_types.remove(deposit_type);
				deposit_types.insert(0, deposit_type);
				break;
		query = """
				SELECT dt.id, dt.kind_id, dt.group_id, dt.type_id, dt.subtype_id, dt.name_ru FROM deposit_types dt 
				WHERE dt.kind_id = %s AND dt.group_id = %s
				AND dt.type_id = %s AND dt.subtype_id <> 0 
				ORDER BY name_ru ASC
				""";
		g.cur.execute(query, [int(deposit_kind_id), int(deposit_group_id), int(deposit_type_id)]);
		rows = g.cur.fetchall();
		deposit_subtypes = [];

		for row in rows:
			deposit_subtypes.append({
				"id": row["id"], 
				"name": row["name_ru"], 
				"kind_id": row["kind_id"], 
				"group_id": row["group_id"],
				"type_id": row["type_id"],
				"subtype_id": row["subtype_id"]
				});
		return make_response(render_template("deposit_subtypes.html", 
			deposit_kinds = deposit_kinds, 
			deposit_groups = deposit_groups,
			deposit_types = deposit_types,
			deposit_subtypes = deposit_subtypes,
			token = get_hash(request.cookies.get("token", None))
			));

@app.route("/delete_deposit_subtype/", methods=["GET", "POST"])
def delete_deposit_subtype():
	if not ip_based_access_control(request.remote_addr, "192.168.0.0"):
		return redirect(url_for('denied'));
	if not is_valid_session(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if not is_admin(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if not is_valid_hash(request.cookies.get("token", None), request.args.get("token", None)):
		return make_response(redirect(url_for("login")));
	if request.method == "GET":
		deposit_kind_id = request.args.get("kind_id", None);
		deposit_group_id = request.args.get("group_id", None);
		deposit_type_id = request.args.get("type_id", None);
		deposit_subtype_id = request.args.get("subtype_id", None);
		if not deposit_kind_id:
			return make_response(redirect(url_for("deposit_subtypes")));
		if not deposit_group_id:
			return make_response(redirect(url_for("deposit_subtypes")));
		if not deposit_type_id:
			return make_response(redirect(url_for("deposit_subtypes")));
		if not deposit_subtype_id:
			return make_response(redirect(url_for("deposit_subtypes")));
		query = """
			DELETE FROM resources 
				WHERE id IN 
					(SELECT resource_id 
						FROM deposit_types 
						WHERE kind_id = %s 
							AND group_id = %s
							AND type_id = %s 
							AND subtype_id = %s)
		""";
		g.cur.execute(query, [
			int(deposit_kind_id), 
			int(deposit_group_id), 
			int(deposit_type_id), 
			int(deposit_subtype_id)]);
		rows = g.db.commit();
		return make_response(redirect(url_for("deposit_subtypes")));
	else:
		return redirect(url_for('login'));

@app.route("/edit_deposit_subtype/", methods=["GET", "POST"])
def edit_deposit_subtype():
	if not ip_based_access_control(request.remote_addr, "192.168.0.0"):
		return redirect(url_for('denied'));
	if not is_valid_session(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if not is_admin(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if request.method == "GET":
		deposit_kind_id = request.args.get("kind_id", None);
		deposit_group_id = request.args.get("group_id", None);
		deposit_type_id = request.args.get("type_id", None);
		deposit_subtype_id = request.args.get("subtype_id", None);
		if not get_deposit_kind(deposit_kind_id):
			return make_response(redirect(url_for("deposit_subtypes")));
		if not get_deposit_group(deposit_kind_id, deposit_group_id):
			return make_response(redirect(url_for("deposit_subtypes")));
		if not get_deposit_type(deposit_kind_id, deposit_group_id, deposit_type_id):
			return make_response(redirect(url_for("deposit_subtypes")));
		if not get_deposit_subtype(deposit_kind_id, deposit_group_id, deposit_type_id, deposit_subtype_id):
			return make_response(redirect(url_for("deposit_subtypes")));
		resource_id = get_resource_id_for_deposit_subtype(
			deposit_kind_id, 
			deposit_group_id, 
			deposit_type_id,
			deposit_subtype_id);
		if not resource_id:
			return make_response(redirect(url_for("deposit_subtypes")));
		return render_template("edit_deposit_subtype.html", 
			deposit_kind_id = deposit_kind_id,
			deposit_group_id = deposit_group_id,
			deposit_type_id = deposit_type_id,
			deposit_subtype_id = deposit_subtype_id,
			deposit_subtype = get_deposit_subtype(deposit_kind_id, deposit_group_id, deposit_type_id, deposit_subtype_id),
			permissions = get_permissions(resource_id), 
			error = None);
	else:
		deposit_kind_id = request.form.get("deposit_kind_id", None);
		deposit_group_id = request.form.get("deposit_group_id", None);
		deposit_type_id = request.form.get("deposit_type_id", None);
		deposit_subtype_id = request.form.get("deposit_subtype_id", None);
		deposit_subtype = request.form.get("deposit_subtype", None);
		if not get_deposit_kind(deposit_kind_id):
			return make_response(redirect(url_for("deposit_subtypes")));
		if not get_deposit_group(deposit_kind_id, deposit_group_id):
			return make_response(redirect(url_for("deposit_subtypes")));
		if not get_deposit_type(deposit_kind_id, deposit_group_id, deposit_type_id):
			return make_response(redirect(url_for("deposit_subtypes")));
		if not get_deposit_subtype(deposit_kind_id, deposit_group_id, deposit_type_id, deposit_subtype_id):			
			return make_response(redirect(url_for("deposit_subtypes")));
		resource_id = get_resource_id_for_deposit_subtype(
			deposit_kind_id, 
			deposit_group_id, 
			deposit_type_id,
			deposit_subtype_id);
		if not resource_id:
			return make_response(redirect(url_for("deposit_subtypes")));
		#Make regular expression here
		if not deposit_subtype or deposit_subtype == "":
			return render_template("edit_deposit_subtype.html", 
				deposit_kind_id = deposit_kind_id,
				deposit_group_id = deposit_group_id,
				deposit_type_id = deposit_type_id,
				deposit_subtype_id = deposit_subtype_id,
				deposit_subtype = get_deposit_subtype(
					deposit_kind_id, 
					deposit_group_id, 
					deposit_type_id, 
					deposit_subtype_id),
				permissions = get_permissions(resource_id), 
				error = "Неверное наименование для подтипа");
		roles = get_roles();
		permitted_roles = get_roles_from_form(request.form, roles);
		update_read_permissions(permitted_roles, resource_id);
		query = """
			UPDATE deposit_types SET name_ru = %s
				WHERE kind_id = %s
					AND group_id = %s
					AND type_id = %s
					AND subtype_id = %s
		""";
		g.cur.execute(query, [deposit_subtype, 
			deposit_kind_id, 
			deposit_group_id, 
			deposit_type_id, 
			deposit_subtype_id]);
		g.db.commit();
		return make_response(redirect(url_for("deposit_subtypes")));

@app.route("/add_deposit_subtype/", methods=["GET", "POST"])
def add_deposit_subtype():
	if not ip_based_access_control(request.remote_addr, "192.168.0.0"):
		return redirect(url_for('denied'));
	if not is_valid_session(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if not is_admin(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if request.method == "GET":
		deposit_kinds = get_deposit_kinds();
		if len(deposit_kinds) == 0:
			return make_response(redirect(url_for("deposit_kinds")));
		deposit_kind_id = deposit_kinds[0]["kind_id"];
		deposit_groups = get_deposit_groups(deposit_kind_id);
		if len(deposit_groups) == 0:
			return make_response(redirect(url_for("deposit_groups")));
		deposit_group_id = deposit_groups[0]["group_id"];
		return render_template("add_deposit_subtype.html", 
			deposit_kinds = get_deposit_kinds(), 
			deposit_groups = get_deposit_groups(deposit_kind_id),
			deposit_types = get_deposit_types(deposit_kind_id, deposit_group_id),
			permissions = get_default_permissions(), 
			error = None);
	elif request.method == "POST":
		deposit_kind_id = request.form.get("deposit_kind_id", None);
		deposit_group_id = request.form.get("deposit_group_id", None);
		deposit_type_id = request.form.get("deposit_type_id", None);
		deposit_subtype = request.form.get("deposit_subtype", None);
		if not deposit_kind_id:
			deposit_kinds = get_deposit_kinds();
			if len(deposit_kinds) == 0:
				return render_template("add_deposit_subtype.html", 
					deposit_kinds = [], 
					deposit_groups = [],
					deposit_types = [],
					permissions = get_default_permissions(), 
					error = u"Неверный вид");
			deposit_kind_id = deposit_kinds[0]["kind_id"];
			deposit_groups = get_deposit_groups(deposit_kind_id);
			if len(get_deposit_groups) == 0:
				return render_template("add_deposit_subtype.html", 
					deposit_kinds = deposit_kinds, 
					deposit_groups = [],
					deposit_types = [],
					permissions = get_default_permissions(), 
					error = u"Неверный вид");
			deposit_group_id = deposit_groups[0]["group_id"];
			return render_template("add_deposit_subtype.html", 
				deposit_kinds = deposit_kinds, 
				deposit_groups = deposit_groups,
				deposit_types = get_deposit_types(deposit_kind_id, deposit_group_id),
				permissions = get_default_permissions(), 
				error = u"Неверный вид");
		if not get_deposit_kind(deposit_kind_id):
			deposit_kinds = get_deposit_kinds();
			if len(deposit_kinds) == 0:
				return render_template("add_deposit_subtype.html", 
					deposit_kinds = [], 
					deposit_groups = [],
					deposit_types = [],
					permissions = get_default_permissions(), 
					error = u"Неверный вид");
			deposit_kind_id = deposit_kinds[0]["kind_id"];
			deposit_groups = get_deposit_groups(deposit_kind_id);
			if len(get_deposit_groups) == 0:
				return render_template("add_deposit_subtype.html", 
					deposit_kinds = deposit_kinds, 
					deposit_groups = [],
					deposit_types = [],
					permissions = get_default_permissions(), 
					error = u"Неверный вид");
			deposit_group_id = deposit_groups[0]["group_id"];
			return render_template("add_deposit_subtype.html", 
				deposit_kinds = deposit_kinds, 
				deposit_groups = deposit_groups,
				deposit_types = get_deposit_types(deposit_kind_id, deposit_group_id),
				permissions = get_default_permissions(), 
				error = u"Неверный вид");
		deposit_kinds = get_deposit_kinds();
		for deposit_kind in deposit_kinds:
			if deposit_kind["kind_id"] == deposit_kind_id:
				deposit_kinds.remove(deposit_kind);
				deposit_kinds.insert(0, deposit_kind);
				break;
		if not deposit_group_id:
			deposit_groups = get_deposit_groups(deposit_kind_id);
			if len(deposit_groups) == 0:
				return render_template("add_deposit_subtype.html", 
					deposit_kinds = deposit_kinds, 
					deposit_groups = [],
					deposit_types = [],
					permissions = get_default_permissions(), 
					error = u"Неверная группа");
			deposit_group_id = deposit_groups[0]["group_id"];
			return render_template("add_deposit_subtype.html", 
				deposit_kinds = deposit_kinds, 
				deposit_groups = deposit_groups,
				deposit_types = get_deposit_types(deposit_kind_id, deposit_group_id),
				permissions = get_default_permissions(), 
				error = u"Неверная группа");
		if not get_deposit_group(deposit_kind_id, deposit_group_id):
			deposit_groups = get_deposit_groups(deposit_kind_id);
			if len(deposit_groups) == 0:
				return render_template("add_deposit_subtype.html", 
					deposit_kinds = deposit_kinds, 
					deposit_groups = [],
					deposit_types = [],
					permissions = get_default_permissions(), 
					error = u"Неверная группа");
			deposit_group_id = deposit_groups[0]["group_id"];
			return render_template("add_deposit_subtype.html", 
				deposit_kinds = deposit_kinds, 
				deposit_groups = deposit_groups,
				deposit_types = get_deposit_types(deposit_kind_id, deposit_group_id),
				permissions = get_default_permissions(), 
				error = u"Неверная группа");
		deposit_groups = get_deposit_groups(deposit_kind_id);
		for deposit_group in deposit_groups:
			if deposit_group["group_id"] == deposit_group_id:
				deposit_groups.remove(deposit_group);
				deposit_groups.insert(0, deposit_group);
				break;
		if not deposit_type_id:
			deposit_types = get_deposit_types(deposit_kind_id, deposit_group_id);
			return render_template("add_deposit_subtype.html", 
				deposit_kinds = deposit_kinds, 
				deposit_groups = deposit_groups,
				deposit_types = deposit_types,
				permissions = get_default_permissions(), 
				error = u"Неверный тип");
		if not get_deposit_type(deposit_kind_id, deposit_group_id, deposit_type_id):
			deposit_types = get_deposit_types(deposit_kind_id, deposit_group_id);
			return render_template("add_deposit_subtype.html", 
				deposit_kinds = deposit_kinds, 
				deposit_groups = deposit_groups,
				deposit_types = deposit_types,
				permissions = get_default_permissions(), 
				error = u"Неверный тип");
		deposit_types = get_deposit_types(deposit_kind_id, deposit_group_id);
		for deposit_type in deposit_types:
			if deposit_type["type_id"] == deposit_type_id:
				deposit_types.remove(deposit_type);
				deposit_types.insert(0, deposit_type);
				break;
		#Make regular expression here
		if not deposit_subtype or deposit_subtype == "":
			return render_template("add_deposit_subtype.html", 
				deposit_kinds = deposit_kinds, 
				deposit_groups = deposit_groups,
				deposit_types = deposit_types,
				permissions = get_default_permissions(), 
				error = u"Неверное наименование для подтипа");
		roles = get_roles();
		permitted_roles = get_roles_from_form(request.form, roles);
		uuid = get_uuid();
		add_resource(uuid);
		add_read_permissions(permitted_roles, uuid);
		query = """
			INSERT INTO deposit_types(
				kind_id, 
				group_id, 
				type_id, 
				subtype_id, 
				name_en, 
				name_ru, 
				name_uz, 
				resource_id)
			VALUES(
				%s, 
				%s,
				%s,
				(SELECT MAX(dt.subtype_id) + 1 
					FROM deposit_types dt 
						WHERE dt.kind_id = %s 
							AND dt.group_id = %s 
							AND dt.type_id = %s),
				"", %s, "",
				(SELECT id FROM resources WHERE name = %s)
			)
		""";
		g.cur.execute(query, [
			int(deposit_kind_id), 
			int(deposit_group_id), 
			int(deposit_type_id),
			int(deposit_kind_id), 
			int(deposit_group_id),
			int(deposit_type_id), 
			deposit_subtype, uuid]);
		g.db.commit();
		return make_response(redirect(url_for("deposit_subtypes")));

@app.route("/minerals/", methods=["GET"])
def minerals():
	if not ip_based_access_control(request.remote_addr, "192.168.0.0"):
		return redirect(url_for('denied'));
	if not is_valid_session(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if not is_admin(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if request.method == "GET":
		amount_unit_id = request.args.get("amount_unit_id", None);
		amount_units = get_amount_units();
		if not amount_unit_id:
			if len(amount_units) > 0:
				amount_unit_id = amount_units[0]["amount_unit_id"];
			else:
				return make_response(render_template("minerals.html", 
					amount_units = [],
					minerals = [],
					token = get_hash(request.cookies.get("token", None))
				));
		else:
			for amount_unit in amount_units:
				if int(amount_unit_id) == amount_unit["amount_unit_id"]:
					amount_units.remove(amount_unit);
					amount_units.insert(0, amount_unit);
					break;
		minerals = get_minerals(amount_unit_id);
		return make_response(render_template("minerals.html", 
				amount_units = amount_units,
				minerals = minerals,
				token = get_hash(request.cookies.get("token", None))
				));

@app.route("/delete_mineral/", methods=["GET"])
def delete_mineral():
	if not ip_based_access_control(request.remote_addr, "192.168.0.0"):
		return redirect(url_for('denied'));
	if not is_valid_session(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if not is_admin(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if not is_valid_hash(request.cookies.get("token", None), request.args.get("token", None)):
		return make_response(redirect(url_for("login")));
	if request.method == "GET":
		mineral_id = request.args.get("mineral_id", None);
		query = """
			DELETE FROM resources 
				WHERE id = (SELECT resource_id FROM minerals WHERE id = %s)
		""";
		g.cur.execute(query, [mineral_id]);
		g.db.commit();
		return make_response(redirect(url_for("minerals")));

@app.route("/add_mineral/", methods = ["GET", "POST"])
def add_mineral():
	if not ip_based_access_control(request.remote_addr, "192.168.0.0"):
		return redirect(url_for('denied'));
	if not is_valid_session(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if not is_admin(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if request.method == "GET":
		amount_units = get_amount_units();
		if len(amount_units) == 0:
			return make_response(redirect(url_for("amount_units")));
		return make_response(render_template("add_mineral.html", 
			amount_units = amount_units, 
			permissions = get_default_permissions(), 
			error = None));
	else:
		amount_unit_id = request.form.get("amount_unit_id", None);
		if not amount_unit_id:
			return make_response(redirect(url_for("minerals")));
		if not get_amount_unit(amount_unit_id):
			return make_response(redirect(url_for("minerals")));
		mineral = request.form.get("mineral", None);
		if check_for_collision_in_mineral(mineral):
			amount_units = get_amount_units();
			return make_response(render_template("add_mineral.html", 
				amount_units = amount_units, 
				permissions = get_default_permissions(), 
				error = u"Неверное название для полезного ископаемого"));
		roles = get_roles();
		permitted_roles = get_roles_from_form(request.form, roles);
		uuid = get_uuid();
		add_resource(uuid);
		add_read_permissions(permitted_roles, uuid);
		query = """
			INSERT INTO minerals(
				amount_unit_id, 
				name_en, 
				name_ru, 
				name_uz, 
				resource_id)
			VALUES(
				%s, 
				"",
				%s,
				"",
				(SELECT id FROM resources WHERE name = %s)
			)
		""";
		g.cur.execute(query, [
			int(amount_unit_id), 
			mineral, 
			uuid]);
		g.db.commit();
		return make_response(redirect(url_for("minerals")));

@app.route("/edit_mineral/", methods = ["GET", "POST"])
def edit_mineral():
	if not ip_based_access_control(request.remote_addr, "192.168.0.0"):
		return redirect(url_for('denied'));
	if not is_valid_session(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if not is_admin(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if request.method == "GET":
		mineral_id = request.args.get("mineral_id");
		if not get_mineral(mineral_id):
			return make_response(redirect(url_for("minerals")));
		resource_id = get_resource_id_for_mineral(mineral_id);
		if not resource_id:
			return make_response(redirect(url_for("minerals")));
		return make_response(render_template("edit_mineral.html", 
			mineral_id = mineral_id, 
			mineral = get_mineral(mineral_id),
			permissions = get_permissions(resource_id), 
			error = None));
	else:
		mineral_id = request.form.get("mineral_id", None);
		if not mineral_id:
			return make_response(redirect(url_for("minerals")));
		if not get_mineral(mineral_id):
			return make_response(redirect(url_for("minerals")));
		mineral = request.form.get("mineral", None);
		if check_for_collision_in_mineral(mineral):
			return make_response(render_template("edit_mineral.html", 
				#amount_units = amount_units, 
				mineral = get_mineral(mineral_id),
				permissions = get_default_permissions(), 
				error = u"Неверное название для полезного ископаемого"));
		roles = get_roles();
		permitted_roles = get_roles_from_form(request.form, roles);
		uuid = get_uuid();
		add_resource(uuid);
		add_read_permissions(permitted_roles, uuid);
		query = """
			UPDATE minerals set name_ru = %s
				WHERE id = %s
		""";
		g.cur.execute(query, [
			mineral, 
			int(mineral_id)]);
		g.db.commit();
		return make_response(redirect(url_for("minerals")));

@app.route("/deposit_statuses/", methods=["GET", "POST"])
def deposit_statuses():
	if not ip_based_access_control(request.remote_addr, "192.168.0.0"):
		return redirect(url_for('denied'));
	if not is_valid_session(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if not is_admin(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if request.method == "GET":
		query = "SELECT id, name_ru FROM deposit_status";
		g.cur.execute(query);
		rows = g.cur.fetchall();
		deposit_statuses = [];
		for row in rows:
			deposit_statuses.append({
				"deposit_status_id": row["id"], 
				"name": row["name_ru"]
				});
		return render_template("deposit_statuses.html", 
			deposit_statuses = deposit_statuses, 
			token = get_hash(request.cookies.get("token", None)));
	else:
		return redirect(url_for('login'));

@app.route("/delete_deposit_status/", methods=["GET", "POST"])
def delete_deposit_status():
	if not ip_based_access_control(request.remote_addr, "192.168.0.0"):
		return redirect(url_for('denied'));
	if not is_valid_session(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if not is_admin(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if not is_valid_hash(request.cookies.get("token", None), request.args.get("token", None)):
		return make_response(redirect(url_for("login")));
	if request.method == "GET":
		deposit_status_id = request.args.get("deposit_status_id", None);
		if not deposit_status_id:
			return make_response(redirect(url_for("deposit_statuses")));
		query = """
			DELETE FROM resources 
				WHERE id = 
					(SELECT resource_id FROM deposit_status WHERE id = %s)
		""";
		g.cur.execute(query, [int(deposit_status_id)]);
		rows = g.db.commit();
		return make_response(redirect(url_for("deposit_statuses")));
	else:
		return redirect(url_for('login'));

@app.route("/add_deposit_status/", methods=["GET", "POST"])
def add_deposit_status():
	if not ip_based_access_control(request.remote_addr, "192.168.0.0"):
		return redirect(url_for('denied'));
	if not is_valid_session(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if not is_admin(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if request.method == "GET":
		return render_template("add_deposit_status.html", 
			permissions = get_default_permissions(), 
			error = None);
	elif request.method == "POST":
		deposit_status = request.form.get("deposit_status", None);
		#Make regular expression here
		if not deposit_status or deposit_status == "":
			return render_template("add_deposit_status.html", 
				permissions = get_default_permissions(), 
				error = u"Неверное наименование для статуса");
		if check_for_collision_in_depsoit_status(deposit_status):
			return render_template("add_deposit_status.html", 
				permissions = get_default_permissions(), 
				error = u"Данный статус уже существует в базе");
		roles = get_roles();
		permitted_roles = get_roles_from_form(request.form, roles);
		uuid = get_uuid();
		add_resource(uuid);
		add_read_permissions(permitted_roles, uuid);
		query = """
			INSERT INTO deposit_status(name_en, name_ru, name_uz, resource_id)
			VALUES(
				"", %s, "",
				(SELECT id FROM resources WHERE name = %s)
			)
		""";
		g.cur.execute(query, [deposit_status, uuid]);
		g.db.commit();
		return make_response(redirect(url_for("deposit_statuses")));

@app.route("/edit_deposit_status/", methods=["GET", "POST"])
def edit_deposit_status():
	if not ip_based_access_control(request.remote_addr, "192.168.0.0"):
		return redirect(url_for('denied'));
	if not is_valid_session(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if not is_admin(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if request.method == "GET":
		deposit_status_id = request.args.get("deposit_status_id", None);
		if not get_deposit_status(deposit_status_id):
			return make_response(redirect(url_for("deposit_statuses")));
		resource_id = get_resource_id_for_deposit_status(deposit_status_id);
		return render_template("edit_depoist_status.html", 
			deposit_status_id = deposit_status_id,
			deposit_status = get_deposit_status(deposit_status_id),
			permissions = get_permissions(resource_id), 
			error = None);
	elif request.method == "POST":
		deposit_status_id = request.form.get("deposit_status_id", None);
		deposit_status = request.form.get("deposit_status", None);
		if not get_deposit_status(deposit_status_id):
			return make_response(redirect(url_for("deposit_statuses")));
		resource_id = get_resource_id_for_deposit_status(deposit_status_id);
		#Make regular expression here
		if not deposit_status or deposit_status == "":
			return render_template("edit_deposit_status.html", 
				deposit_status_id = deposit_status_id,
				deposit_status = get_deposit_status(deposit_status_id),
				permissions = get_permissions(resource_id),
				error = u"Неверное наименование для статуса");
		roles = get_roles();
		permitted_roles = get_roles_from_form(request.form, roles);
		update_read_permissions(permitted_roles, resource_id);
		query = """
			UPDATE deposit_status SET name_ru = %s
				WHERE id = %s
		""";
		g.cur.execute(query, [deposit_status, deposit_status_id]);
		g.db.commit();
		return make_response(redirect(url_for("deposit_statuses")));

@app.route("/companies/", methods=["GET", "POST"])
def companies():
	if not ip_based_access_control(request.remote_addr, "192.168.0.0"):
		return redirect(url_for('denied'));
	if not is_valid_session(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if not is_admin(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if request.method == "GET":
		query = "SELECT id, name_ru FROM companies ORDER BY name_ru ASC";
		g.cur.execute(query);
		rows = g.cur.fetchall();
		companies = [];
		for row in rows:
			companies.append({
				"company_id": row["id"], 
				"name": row["name_ru"]
				});
		return render_template("companies.html", 
			companies = companies, 
			token = get_hash(request.cookies.get("token", None)));
	else:
		return redirect(url_for('login'));

@app.route("/delete_company/", methods=["GET", "POST"])
def delete_company():
	if not ip_based_access_control(request.remote_addr, "192.168.0.0"):
		return redirect(url_for('denied'));
	if not is_valid_session(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if not is_admin(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if not is_valid_hash(request.cookies.get("token", None), request.args.get("token", None)):
		return make_response(redirect(url_for("login")));
	if request.method == "GET":
		company_id = request.args.get("company_id", None);
		if not company_id:
			return make_response(redirect(url_for("companies")));
		query = """
			DELETE FROM resources 
				WHERE id = 
					(SELECT resource_id FROM companies WHERE id = %s)
		""";
		g.cur.execute(query, [int(company_id)]);
		rows = g.db.commit();
		return make_response(redirect(url_for("companies")));
	else:
		return redirect(url_for('login'));

@app.route("/add_company/", methods=["GET", "POST"])
def add_company():
	if not ip_based_access_control(request.remote_addr, "192.168.0.0"):
		return redirect(url_for('denied'));
	if not is_valid_session(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if not is_admin(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if request.method == "GET":
		return render_template("add_company.html", 
			permissions = get_default_permissions(), 
			error = None);
	elif request.method == "POST":
		company = request.form.get("company", None);
		#Make regular expression here
		if not company or company == "":
			return render_template("add_company.html", 
				permissions = get_default_permissions(), 
				error = u"Неверное наименование для организации");
		if check_for_collision_in_company(company):
			return render_template("add_company.html", 
				permissions = get_default_permissions(), 
				error = u"Данная организация уже существует в базе");
		roles = get_roles();
		permitted_roles = get_roles_from_form(request.form, roles);
		uuid = get_uuid();
		add_resource(uuid);
		add_read_permissions(permitted_roles, uuid);
		query = """
			INSERT INTO companies(name_en, name_ru, name_uz, resource_id)
			VALUES(
				"", %s, "",
				(SELECT id FROM resources WHERE name = %s)
			)
		""";
		g.cur.execute(query, [company, uuid]);
		g.db.commit();
		return make_response(redirect(url_for("companies")));

@app.route("/edit_company/", methods=["GET", "POST"])
def edit_company():
	if not ip_based_access_control(request.remote_addr, "192.168.0.0"):
		return redirect(url_for('denied'));
	if not is_valid_session(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if not is_admin(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if request.method == "GET":
		company_id = request.args.get("company_id", None);
		if not get_company(company_id):
			return make_response(redirect(url_for("companies")));
		resource_id = get_resource_id_for_company(company_id);
		return render_template("edit_company.html", 
			company_id = company_id,
			company = get_company(company_id),
			permissions = get_permissions(resource_id), 
			error = None);
	elif request.method == "POST":
		company_id = request.form.get("company_id", None);
		company = request.form.get("company", None);
		if not get_company(company_id):
			return make_response(redirect(url_for("companies")));
		resource_id = get_resource_id_for_company(company_id);
		#Make regular expression here
		if not company or company == "":
			return render_template("edit_company.html", 
				company_id = company_id,
				company = get_company(company_id),
				permissions = get_permissions(resource_id),
				error = u"Неверное наименование для организации");
		roles = get_roles();
		permitted_roles = get_roles_from_form(request.form, roles);
		update_read_permissions(permitted_roles, resource_id);
		query = """
			UPDATE companies SET name_ru = %s
				WHERE id = %s
		""";
		g.cur.execute(query, [company, company_id]);
		g.db.commit();
		return make_response(redirect(url_for("companies")));

@app.route("/sites/", methods=["GET"])
def sites():
	if not ip_based_access_control(request.remote_addr, "192.168.0.0"):
		return redirect(url_for('denied'));
	if not is_valid_session(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if not is_admin(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if request.method == "GET":
		sites = get_sites();
		return make_response(render_template("sites.html", 
				sites = sites,
				token = get_hash(request.cookies.get("token", None))
				));

@app.route("/delete_site/", methods=["GET"])
def delete_site():
	if not ip_based_access_control(request.remote_addr, "192.168.0.0"):
		return redirect(url_for('denied'));
	if not is_valid_session(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if not is_admin(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if not is_valid_hash(request.cookies.get("token", None), request.args.get("token", None)):
		return make_response(redirect(url_for("login")));
	if request.method == "GET":
		site_id = request.args.get("site_id", None);
		query = """
			DELETE FROM resources 
				WHERE id = (SELECT resource_id FROM sites WHERE id = %s)
		""";
		g.cur.execute(query, [site_id]);
		g.db.commit();
		return make_response(redirect(url_for("sites")));

@app.route("/add_site/", methods=["GET", "POST"])
def add_site():
	if not ip_based_access_control(request.remote_addr, "192.168.0.0"):
		return redirect(url_for('denied'));
	if not is_valid_session(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if not is_admin(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if request.method == "GET":
		return render_template("add_site.html", 
			permissions = get_default_permissions(), 
			error = None);
	elif request.method == "POST":
		site = request.form.get("site", None);
		#Make regular expression here
		if not site or site == "":
			return render_template("add_site.html", 
				permissions = get_default_permissions(), 
				error = u"Неверное наименование для участка");
		if check_for_collision_in_site(site):
			return render_template("add_site.html", 
				permissions = get_default_permissions(), 
				error = u"Данный участок уже существует в базе");
		roles = get_roles();
		permitted_roles = get_roles_from_form(request.form, roles);
		uuid = get_uuid();
		add_resource(uuid);
		add_read_permissions(permitted_roles, uuid);
		query = """
			INSERT INTO sites(name_en, name_ru, name_uz, resource_id)
			VALUES(
				"", %s, "",
				(SELECT id FROM resources WHERE name = %s)
			)
		""";
		g.cur.execute(query, [site, uuid]);
		g.db.commit();
		return make_response(redirect(url_for("sites")));

@app.route("/edit_site/", methods=["GET", "POST"])
def edit_site():
	if not ip_based_access_control(request.remote_addr, "192.168.0.0"):
		return redirect(url_for('denied'));
	if not is_valid_session(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if not is_admin(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if request.method == "GET":
		site_id = request.args.get("site_id", None);
		if not get_site(site_id):
			return make_response(redirect(url_for("sites")));
		resource_id = get_resource_id_for_site(site_id);
		return render_template("edit_site.html", 
			site_id = site_id,
			site = get_site(site_id),
			permissions = get_permissions(resource_id), 
			error = None);
	elif request.method == "POST":
		site_id = request.form.get("site_id", None);
		site = request.form.get("site", None);
		if not get_site(site_id):
			return make_response(redirect(url_for("licenses")));
		resource_id = get_resource_id_for_site(site_id);
		#Make regular expression here
		if not site or site == "":
			return render_template("edit_site.html", 
				site_id = site_id,
				site = get_site(site_id),
				permissions = get_permissions(resource_id),
				error = u"Неверное наименование для участка");
		roles = get_roles();
		permitted_roles = get_roles_from_form(request.form, roles);
		update_read_permissions(permitted_roles, resource_id);
		query = """
			UPDATE sites SET name_ru = %s
				WHERE id = %s
		""";
		g.cur.execute(query, [site, site_id]);
		g.db.commit();
		return make_response(redirect(url_for("sites")));

@app.route("/licenses/", methods=["GET"])
def licenses():
	if not ip_based_access_control(request.remote_addr, "192.168.0.0"):
		return redirect(url_for('denied'));
	if not is_valid_session(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if not is_admin(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if request.method == "GET":
		licenses = get_licenses();
		return make_response(render_template("licenses.html", 
				licenses = licenses,
				token = get_hash(request.cookies.get("token", None))
				));

@app.route("/delete_license/", methods=["GET"])
def delete_license():
	if not ip_based_access_control(request.remote_addr, "192.168.0.0"):
		return redirect(url_for('denied'));
	if not is_valid_session(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if not is_valid_hash(request.cookies.get("token", None), request.args.get("token", None)):
		return make_response(redirect(url_for("login")));
	if not is_admin(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if request.method == "GET":
		license_id = request.args.get("license_id", None);
		query = """
			DELETE FROM resources 
				WHERE id = (SELECT resource_id FROM licenses WHERE id = %s)
		""";
		g.cur.execute(query, [license_id]);
		g.db.commit();
		return make_response(redirect(url_for("licenses")));

@app.route("/edit_license/", methods=["GET", "POST"])
def edit_license():
	if not ip_based_access_control(request.remote_addr, "192.168.0.0"):
		return redirect(url_for('denied'));
	if not is_valid_session(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if not is_admin(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if request.method == "GET":
		license_id = request.args.get("license_id", None);
		# License cannot be empty string
		if get_license(license_id) == None:
			return make_response(redirect(url_for("licenses")));
		resource_id = get_resource_id_for_license(license_id);
		return render_template("edit_license.html", 
			license_id = license_id,
			license = get_license(license_id),
			date_of_issue = get_license_date_of_issue(license_id),
			permissions = get_permissions(resource_id), 
			error = None);
	elif request.method == "POST":
		license_id = request.form.get("license_id", None);
		license = request.form.get("license", None);
		date_of_issue = request.form.get("date_of_issue", None);
		# License cannot be empty string
		if get_license(license_id) == None:
			return make_response(redirect(url_for("licenses")));
		resource_id = get_resource_id_for_license(license_id);
		if not re.match("^[0-9]{2,4}-[0-9]{2}-[0-9]{2}$", date_of_issue):
			return render_template("edit_license.html", 
				license_id = license_id,
				license = get_license(license_id),
				date_of_issue = get_license_date_of_issue(license_id),
				permissions = get_permissions(resource_id), 
				error = u"Неверная дата выдачи лицензии");
		try:
			date_of_issue = datetime.datetime.strptime(date_of_issue, "%Y-%m-%d");
		except:
			return render_template("edit_license.html", 
				license_id = license_id,
				license = get_license(license_id),
				date_of_issue = get_license_date_of_issue(license_id),
				permissions = get_permissions(resource_id), 
				error = u"Неверная дата выдачи лицензии");
		if not re.match("^[A-Z]{2}\\s[A-Z]{1}\\s[0-9]{4}\\s[A-Z]{1}[0-9]{1}$", license):
			return render_template("edit_license.html", 
				license_id = license_id,
				license = get_license(license_id),
				date_of_issue = get_license_date_of_issue(license_id),
				permissions = get_permissions(resource_id), 
				error = u"Неверный номер лицензии");
		if check_for_collision_in_license(license, license_id):
			return render_template("edit_license.html", 
				license_id = license_id,
				license = get_license(license_id),
				date_of_issue = get_license_date_of_issue(license_id),
				permissions = get_permissions(resource_id), 
				error = u"Данная лицензия уже существует в базе");
		roles = get_roles();
		permitted_roles = get_roles_from_form(request.form, roles);
		update_read_permissions(permitted_roles, resource_id);
		query = """
			UPDATE licenses SET license = %s, date_of_issue = %s
				WHERE id = %s
		""";
		g.cur.execute(query, [license, date_of_issue, license_id]);
		g.db.commit();
		return make_response(redirect(url_for("licenses")));

@app.route("/get_companies_ajax/", methods=["GET"])
def get_companies_ajax():
	if not ip_based_access_control(request.remote_addr, "192.168.0.0"):
		return jsonify([]);
	if not is_valid_session(request.cookies.get("token", None)):
		return jsonify([]);
	if not is_admin(request.cookies.get("token", None)):
		return jsonify([]);
	if request.method == "GET":
		partial_company_name = request.args.get("partial_company_name", "");
		return jsonify(get_companies(partial_company_name));
	else:
		return jsonify([]);

@app.route("/add_license/", methods=["GET", "POST"])
def add_license():
	if not ip_based_access_control(request.remote_addr, "192.168.0.0"):
		return redirect(url_for('denied'));
	if not is_valid_session(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if not is_admin(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if request.method == "GET":
		return render_template("add_license.html", 
			permissions = get_default_permissions(),
			error = None);
	elif request.method == "POST":
		company_id = request.form.get("company_id", None);
		license = request.form.get("license", None);
		date_of_issue = request.form.get("date_of_issue", None);
		if not re.match("^[0-9]{2,4}-[0-9]{2}-[0-9]{2}$", date_of_issue):
			return render_template("add_license.html", 
				permissions = get_default_permissions(), 
				error = u"Неверная дата выдачи лицензии");
		try:
			date_of_issue = datetime.datetime.strptime(date_of_issue, "%Y-%m-%d");
		except:
			return render_template("add_license.html", 
				permissions = get_default_permissions(), 
				error = u"Неверная дата выдачи лицензии");
		if not re.match("^[A-Z]{2}\\s[A-Z]{1}\\s[0-9]{4}\\s[A-Z]{1}[0-9]{1}$", license):
			return render_template("add_license.html", 
				permissions = get_default_permissions(), 
				error = u"Неверный номер лицензии");
		if check_for_collision_in_license_on_addition(license):
			return render_template("add_license.html", 
				permissions = get_default_permissions(),
				error = u"Данная лицензия уже существует в базе");
		if not get_company(company_id):
			return render_template("add_license.html", 
				permissions = get_default_permissions(), 
				error = u"Данная организация не существует в базе данных");
		roles = get_roles();
		permitted_roles = get_roles_from_form(request.form, roles);
		uuid = get_uuid();
		add_resource(uuid);
		add_read_permissions(permitted_roles, uuid);
		query = """
			INSERT INTO licenses(license, date_of_issue, company_id, resource_id)
			VALUES(
				%s, %s, %s,
				(SELECT id FROM resources WHERE name = %s)
			)
		""";
		g.cur.execute(query, [license, date_of_issue, company_id, uuid]);
		g.db.commit();
		return make_response(redirect(url_for("licenses")));

@app.route("/deposits/", methods=["GET"])
def deposits():
	if not ip_based_access_control(request.remote_addr, "192.168.0.0"):
		return redirect(url_for('denied'));
	if not is_valid_session(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if not is_admin(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if request.method == "GET":
		deposits = get_deposits();
		return make_response(render_template("deposits.html", 
				deposits = deposits,
				token = get_hash(request.cookies.get("token", None))
				));


@app.route("/delete_deposit/", methods=["GET"])
def delete_deposit():
	if not ip_based_access_control(request.remote_addr, "192.168.0.0"):
		return redirect(url_for('denied'));
	if not is_valid_session(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if not is_valid_hash(request.cookies.get("token", None), request.args.get("token", None)):
		return make_response(redirect(url_for("login")));
	if not is_admin(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if request.method == "GET":
		deposit_id = request.args.get("deposit_id", None);
		query = """
			DELETE FROM resources 
				WHERE id = (SELECT resource_id FROM deposits WHERE id = %s)
		""";
		g.cur.execute(query, [deposit_id]);
		g.db.commit();
		return make_response(redirect(url_for("deposits")));


@app.route("/add_deposit/", methods=["GET", "POST"])
def add_deposit():
	if not ip_based_access_control(request.remote_addr, "192.168.0.0"):
		return redirect(url_for('denied'));
	if not is_valid_session(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if not is_admin(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if request.method == "GET":
		return render_template("add_deposit.html", 
			permissions = get_default_permissions(), 
			error = None);
	elif request.method == "POST":
		deposit = request.form.get("deposit", None);
		#Make regular expression here
		if not deposit or deposit == "":
			return render_template("add_deposit.html", 
				permissions = get_default_permissions(), 
				error = u"Неверное наименование для месторождения");
		if check_for_collision_in_deposit(deposit):
			return render_template("add_deposit.html", 
				permissions = get_default_permissions(), 
				error = u"Данное месторождение уже существует в базе");
		roles = get_roles();
		permitted_roles = get_roles_from_form(request.form, roles);
		uuid = get_uuid();
		add_resource(uuid);
		add_read_permissions(permitted_roles, uuid);
		query = """
			INSERT INTO deposits(name_en, name_ru, name_uz, resource_id)
			VALUES(
				"", %s, "",
				(SELECT id FROM resources WHERE name = %s)
			)
		""";
		g.cur.execute(query, [deposit, uuid]);
		g.db.commit();
		return make_response(redirect(url_for("deposits")));

@app.route("/edit_deposit/", methods=["GET", "POST"])
def edit_deposit():
	if not ip_based_access_control(request.remote_addr, "192.168.0.0"):
		return redirect(url_for('denied'));
	if not is_valid_session(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if not is_admin(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if request.method == "GET":	
		deposit_id = request.args.get("deposit_id", None);
		if get_deposit(deposit_id) == None:
			return make_response(redirect(url_for("deposits")));
		resource_id = get_resource_id_for_deposit(deposit_id);
		return render_template("edit_deposit.html", 
			deposit_id = deposit_id,
			deposit = get_deposit(deposit_id),
			permissions = get_permissions(resource_id), 
			error = None);
	elif request.method == "POST":
		deposit_id = request.form.get("deposit_id", None);
		deposit = request.form.get("deposit", None);
		if not get_deposit(deposit_id):
			return make_response(redirect(url_for("deposits")));
		resource_id = get_resource_id_for_deposit(deposit_id);
		#Make regular expression here
		if not deposit or deposit == "":
			return render_template("edit_deposit.html", 
				deposit_id = deposit_id,
				deposit = get_deposit(deposit_id),
				permissions = get_permissions(resource_id),
				error = u"Неверное наименование для месторождения");
		roles = get_roles();
		permitted_roles = get_roles_from_form(request.form, roles);
		update_read_permissions(permitted_roles, resource_id);
		query = """
			UPDATE deposits SET name_ru = %s
				WHERE id = %s
		""";
		g.cur.execute(query, [deposit, deposit_id]);
		g.db.commit();
		return make_response(redirect(url_for("deposits")));

@app.route("/deposits_sites/", methods=["GET"])
def deposits_sites():
	if not ip_based_access_control(request.remote_addr, "192.168.0.0"):
		return redirect(url_for('denied'));
	if not is_valid_session(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if not is_admin(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if request.method == "GET":
		deposits_sites = get_deposits_sites();
		return make_response(render_template("deposits_sites.html", 
				deposits_sites = deposits_sites,
				token = get_hash(request.cookies.get("token", None))
				));


@app.route("/delete_deposit_site/", methods=["GET"])
def delete_deposit_site():
	if not ip_based_access_control(request.remote_addr, "192.168.0.0"):
		return redirect(url_for('denied'));
	if not is_valid_session(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if not is_valid_hash(request.cookies.get("token", None), request.args.get("token", None)):
		return make_response(redirect(url_for("login")));
	if not is_admin(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if request.method == "GET":
		deposit_site_id = request.args.get("deposit_site_id", None);
		query = """
			DELETE FROM resources 
				WHERE id = (SELECT resource_id FROM deposits_sites WHERE id = %s)
		""";
		g.cur.execute(query, [deposit_site_id]);
		g.db.commit();
		return make_response(redirect(url_for("deposits_sites")));

@app.route("/get_deposits_ajax/", methods=["GET"])
def get_deposits_ajax():
	if not ip_based_access_control(request.remote_addr, "192.168.0.0"):
		return jsonify([]);
	if not is_valid_session(request.cookies.get("token", None)):
		return jsonify([]);
	if not is_admin(request.cookies.get("token", None)):
		return jsonify([]);
	if request.method == "GET":
		partial_deposit_name = request.args.get("partial_deposit_name", "");
		return jsonify(get_deposits_by_name(partial_deposit_name));
	else:
		return jsonify([]);

@app.route("/get_sites_ajax/", methods=["GET"])
def get_sites_ajax():
	if not ip_based_access_control(request.remote_addr, "192.168.0.0"):
		return jsonify([]);
	if not is_valid_session(request.cookies.get("token", None)):
		return jsonify([]);
	if not is_admin(request.cookies.get("token", None)):
		return jsonify([]);
	if request.method == "GET":
		partial_site_name = request.args.get("partial_site_name", "");
		return jsonify(get_sites_by_name(partial_site_name));
	else:
		return jsonify([]);

@app.route("/get_deposits_sites_ajax/", methods=["GET"])
def get_deposits_sites_ajax():
	if not ip_based_access_control(request.remote_addr, "192.168.0.0"):
		return jsonify([]);
	if not is_valid_session(request.cookies.get("token", None)):
		return jsonify([]);
	if not is_admin(request.cookies.get("token", None)):
		return jsonify([]);
	if request.method == "GET":
		partial_deposit_site_name = request.args.get("partial_deposit_site_name", "");
		return jsonify(get_deposits_sites_by_name(partial_deposit_site_name));
	else:
		return jsonify([]);

@app.route("/get_minerals_ajax/", methods=["GET"])
def get_minerals_ajax():
	if not ip_based_access_control(request.remote_addr, "192.168.0.0"):
		return jsonify([]);
	if not is_valid_session(request.cookies.get("token", None)):
		return jsonify([]);
	if not is_admin(request.cookies.get("token", None)):
		return jsonify([]);
	if request.method == "GET":
		partial_mineral_name = request.args.get("partial_mineral_name", "");
		return jsonify(get_minerals_by_name(partial_mineral_name));
	else:
		return jsonify([]);

@app.route("/get_areas_ajax/", methods=["GET"])
def get_areas_ajax():
	if not ip_based_access_control(request.remote_addr, "192.168.0.0"):
		return jsonify([]);
	if not is_valid_session(request.cookies.get("token", None)):
		return jsonify([]);
	if not is_admin(request.cookies.get("token", None)):
		return jsonify([]);
	if request.method == "GET":
		region_id = request.args.get("region_id", "");
		return jsonify(get_areas(region_id));
	else:
		return jsonify([]);

@app.route("/add_deposit_site/", methods=["GET", "POST"])
def add_deposit_site():
	if not ip_based_access_control(request.remote_addr, "192.168.0.0"):
		return redirect(url_for('denied'));
	if not is_valid_session(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if not is_admin(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if request.method == "GET":
		regions = get_regions();
		if len(regions) == 0:
			areas = []
		else:
			region_id = regions[0]["region_id"];
			areas = get_areas(region_id);
		return render_template("add_deposit_site.html", 
			permissions = get_default_permissions(), 
			regions = regions,
			areas = areas,
			error = None);
	elif request.method == "POST":
		deposit_id = request.form.get("deposit_id", None);
		site_id = request.form.get("site_id", None);

		query = "SELECT id FROM deposits_sites WHERE deposit_id = %s AND site_id = %s";
		g.cur.execute(query, [deposit_id, site_id]);
		rows = g.cur.fetchall();
		if len(rows) > 0:
			regions = get_regions();
			if len(regions) == 0:
				areas = []
			else:
				region_id = regions[0]["region_id"];
				areas = get_areas(region_id);
			return render_template("add_deposit_site.html", 
				permissions = get_default_permissions(), 
				regions = regions,
				areas = areas,
				error = u"Данная пара месторождение/участок уже существуют в базе");

		if not deposit_id:
			regions = get_regions();
			if len(regions) == 0:
				areas = []
			else:
				region_id = regions[0]["region_id"];
				areas = get_areas(region_id);
			return render_template("add_deposit_site.html", 
				permissions = get_default_permissions(), 
				regions = regions,
				areas = areas,
				error = u"Неверное значение для месторождения");

		if not site_id:
			regions = get_regions();
			if len(regions) == 0:
				areas = []
			else:
				region_id = regions[0]["region_id"];
				areas = get_areas(region_id);
			return render_template("add_deposit_site.html", 
				permissions = get_default_permissions(), 
				regions = regions,
				areas = areas,
				error = u"Неверное значение для участка");

		region_id = request.form.get("region_id", None);
		area_id = request.form.get("area_id", None);

		query = "SELECT id FROM areas WHERE region_id = %s AND area_id = %s";
		g.cur.execute(query, [region_id, area_id]);
		row = g.cur.fetchone();
		if not row:
			regions = get_regions();
			if len(regions) == 0:
				areas = []
			else:
				region_id = regions[0]["region_id"];
				areas = get_areas(region_id);
			return render_template("add_deposit_site.html", 
				permissions = get_default_permissions(), 
				regions = regions,
				areas = areas,
				error = u"Задана неверная область или район");

		region_area_id = row["id"];

		lat = request.form.get("lat", None);
		lon = request.form.get("lon", None);

		image_cut = request.files["cut"];
		image_plan = request.files["plan"];

		roles = get_roles();
		permitted_roles = get_roles_from_form(request.form, roles);
		
		image_cut_id = None;
		image_plan_id = None;

		if image_cut:
			uuid = get_uuid();
			add_resource(uuid);
			add_read_permissions(permitted_roles, uuid);

			query = """
				INSERT INTO images(name, data, resource_id)
				VALUES(%s, %s, (SELECT id FROM resources WHERE name = %s));
				""";

			g.cur.execute(query, [image_cut.filename, base64.b64encode(image_cut.read()), uuid]);
			image_cut_id = g.cur.lastrowid;
		else:
			query = """
				SELECT id FROM images WHERE name LIKE 'Нет графики.jpg'
			"""
			g.cur.execute(query, []);
			row = g.cur.fetchone();
			image_cut_id = row["id"];

		if image_plan:
			uuid = get_uuid();
			add_resource(uuid);
			add_read_permissions(permitted_roles, uuid);

			query = """
				INSERT INTO images(name, data, resource_id)
				VALUES(%s, %s, (SELECT id FROM resources WHERE name = %s));
				""";

			g.cur.execute(query, [image_plan.filename, base64.b64encode(image_plan.read()), uuid]);
			image_plan_id = g.cur.lastrowid;
		else:
			query = """
				SELECT id FROM images WHERE name LIKE 'Нет графики.jpg'
			"""
			g.cur.execute(query, []);
			row = g.cur.fetchone();
			image_plan_id = row["id"];
		
		uuid = get_uuid();
		add_resource(uuid);
		add_read_permissions(permitted_roles, uuid);
		print(lat);
		print(lon);
		query = """
			INSERT INTO deposits_sites(region_area_id, deposit_id, site_id, latitude, longitude, image_cut_id, image_plan_id, resource_id)
			VALUES(
				%s, %s, %s, %s, %s, %s, %s, 
				(SELECT id FROM resources WHERE name = %s)
			)
		""";
		g.cur.execute(query, [region_area_id, deposit_id, site_id, lat, lon, image_cut_id, image_plan_id, uuid]);
		g.db.commit();
		return make_response(redirect(url_for("deposits_sites")));

@app.route("/edit_deposit_site/", methods=["GET", "POST"])
def edit_deposit_site():
	if not ip_based_access_control(request.remote_addr, "192.168.0.0"):
		return redirect(url_for('denied'));
	if not is_valid_session(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if not is_admin(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if request.method == "GET":
		deposit_site_id = request.args.get("deposit_site_id", None);
		resource_id = get_resource_id_for_deposit_site(deposit_site_id);
		query = """
			SELECT ds.id, d.name_ru AS deposit_name, s.name_ru AS site_name, 
			(SELECT aa.name_ru AS area_name FROM areas aa WHERE aa.id = ds.region_area_id) AS area_name,
			(SELECT aa.name_ru AS region_name FROM areas aa WHERE aa.region_id = 
				(SELECT aaa.region_id FROM areas aaa WHERE aaa.id = ds.region_area_id) AND aa.area_id=0) AS region_name,
			ds.latitude, ds.longitude
			FROM deposits_sites ds 
			INNER JOIN sites s ON s.id = ds.site_id
			INNER JOIN deposits d ON d.id = ds.deposit_id
			WHERE ds.id = %s
		""";
		g.cur.execute(query, [deposit_site_id]);
		row = g.cur.fetchone();

		if not row:
			return make_response(redirect(url_for("deposits_sites")));

		return render_template("edit_deposit_site.html", 
			permissions = get_permissions(resource_id),
			region = row["region_name"],
			area = row["area_name"],
			site = row["site_name"],
			deposit = row["deposit_name"],
			deposit_site_id = row["id"],
			lat = row["latitude"],
			lon = row["longitude"],
			error = None);
	elif request.method == "POST":
		deposit_site_id = request.form.get("deposit_site_id", None);
		lat = request.form.get("lat", None);
		lon = request.form.get("lon", None);

		try:
			lat = float(lat);
		except:
			lat = -100;
		try:
			lon = float(lon);
		except:
			lon = - 360;

		if lat < -90.0 or lat > 90.0:
			resource_id = get_resource_id_for_deposit_site(deposit_site_id);
			query = """
				SELECT ds.id, d.name_ru AS deposit_name, s.name_ru AS site_name, 
				(SELECT aa.name_ru AS area_name FROM areas aa WHERE aa.id = ds.region_area_id) AS area_name,
				(SELECT aa.name_ru AS region_name FROM areas aa WHERE aa.region_id = 
					(SELECT aaa.region_id FROM areas aaa WHERE aaa.id = ds.region_area_id) AND aa.area_id=0) AS region_name,
				ds.latitude, ds.longitude
				FROM deposits_sites ds 
				INNER JOIN sites s ON s.id = ds.site_id
				INNER JOIN deposits d ON d.id = ds.deposit_id
				WHERE ds.id = %s
			""";
			g.cur.execute(query, [deposit_site_id]);
			row = g.cur.fetchone();

			if not row:
				return make_response(redirect(url_for("deposits_sites")));

			return render_template("edit_deposit_site.html", 
				permissions = get_permissions(resource_id),
				region = row["region_name"],
				area = row["area_name"],
				site = row["site_name"],
				deposit = row["deposit_name"],
				deposit_site_id = row["id"],
				lat = row["latitude"],
				lon = row["longitude"],
				error = u"Неверное значение для широты");
		if lon < -180 or lon > 180:
			resource_id = get_resource_id_for_deposit_site(deposit_site_id);
			query = """
				SELECT ds.id, d.name_ru AS deposit_name, s.name_ru AS site_name, 
				(SELECT aa.name_ru AS area_name FROM areas aa WHERE aa.id = ds.region_area_id) AS area_name,
				(SELECT aa.name_ru AS region_name FROM areas aa WHERE aa.region_id = 
					(SELECT aaa.region_id FROM areas aaa WHERE aaa.id = ds.region_area_id) AND aa.area_id=0) AS region_name,
				ds.latitude, ds.longitude
				FROM deposits_sites ds 
				INNER JOIN sites s ON s.id = ds.site_id
				INNER JOIN deposits d ON d.id = ds.deposit_id
				WHERE ds.id = %s
			""";
			g.cur.execute(query, [deposit_site_id]);
			row = g.cur.fetchone();

			if not row:
				return make_response(redirect(url_for("deposits_sites")));

			return render_template("edit_deposit_site.html", 
				permissions = get_permissions(resource_id),
				region = row["region_name"],
				area = row["area_name"],
				site = row["site_name"],
				deposit = row["deposit_name"],
				deposit_site_id = row["id"],
				lat = row["latitude"],
				lon = row["longitude"],
				error = u"Неверное значение для долготы");
		
		resource_id = get_resource_id_for_deposit_site(deposit_site_id);
		roles = get_roles();
		permitted_roles = get_roles_from_form(request.form, roles);
		update_read_permissions(permitted_roles, resource_id);

		query = """
			UPDATE deposits_sites
			SET latitude = %s, longitude = %s
			WHERE id = %s
		""";
		g.cur.execute(query, [lat, lon, deposit_site_id]);
		g.db.commit();
		return make_response(redirect(url_for("deposits_sites")));

@app.route("/deposits_sites_types/", methods=["GET"])
def deposits_sites_types():
	if not ip_based_access_control(request.remote_addr, "192.168.0.0"):
		return redirect(url_for('denied'));
	if not is_valid_session(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if not is_admin(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if request.method == "GET":
		dst = get_deposits_sites_types();
		return make_response(render_template("deposits_sites_types.html", 
				deposits_sites_types = dst,
				token = get_hash(request.cookies.get("token", None))
				));


@app.route("/delete_deposit_site_type/", methods=["GET"])
def delete_deposit_site_type():
	if not ip_based_access_control(request.remote_addr, "192.168.0.0"):
		return redirect(url_for('denied'));
	if not is_valid_session(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if not is_valid_hash(request.cookies.get("token", None), request.args.get("token", None)):
		return make_response(redirect(url_for("login")));
	if not is_admin(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if request.method == "GET":
		deposit_site_type_id = request.args.get("deposit_site_type_id", None);
		query = """
			DELETE FROM resources 
				WHERE id = (SELECT resource_id FROM deposits_sites_types WHERE id = %s)
		""";
		g.cur.execute(query, [deposit_site_type_id]);
		g.db.commit();
		return make_response(redirect(url_for("deposits_sites_types")));

@app.route("/add_deposit_site_type/", methods=["GET", "POST"])
def add_deposit_site_type():
	if not ip_based_access_control(request.remote_addr, "192.168.0.0"):
		return redirect(url_for('denied'));
	if not is_valid_session(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if not is_admin(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if request.method == "GET":
		deposit_kinds = get_deposit_kinds_all();
		statuses = get_statuses();
		minerals = get_minerals_all();
		return make_response(render_template("add_deposit_site_type.html", 
			kinds = deposit_kinds,
			statuses = statuses,
			minerals = minerals,
			permissions = get_default_permissions()));
	elif request.method == "POST":
		kind_id = request.form.get("kind_id", None);
		group_id = request.form.get("group_id", None);
		type_id = request.form.get("type_id", None);
		subtype_id = request.form.get("subtype_id", None);
		deposit_site_id = request.form.get("deposit_site_id", None);
		mineral_id = request.form.get("mineral_id", None);
		status_id = request.form.get("status_id", None);
		amount_a_b_c1 = request.form.get("amount_a_b_c1", None);
		amount_c2 = request.form.get("amount_c2", None);
		description = request.form.get("description", None);

		roles = get_roles();
		permitted_roles = get_roles_from_form(request.form, roles);
		uuid = get_uuid();
		add_resource(uuid);
		add_read_permissions(permitted_roles, uuid);

		query = """
			SELECT id FROM deposit_types 
				WHERE kind_id = %s 
					AND group_id = %s 
					AND type_id = %s 
					AND subtype_id = %s
		""";

		g.cur.execute(query, [kind_id, group_id, type_id, subtype_id]);
		row = g.cur.fetchone();
		if not row:
			deposit_kinds = get_deposit_kinds_all();
			statuses = get_statuses();
			minerals = get_minerals_all();
			return make_response(render_template("add_deposit_site_type.html", 
				kinds = deposit_kinds,
				statuses = statuses,
				minerals = minerals,
				permissions = get_default_permissions(),
				error = u"Неверный код направления использования"));

		type_group_id = row["id"];

		query = "SELECT * FROM deposits_sites_types WHERE deposit_site_id = %s AND type_group_id = %s";

		g.cur.execute(query, [int(deposit_site_id), int(type_group_id)]);
		row = g.cur.fetchone();
		if row:
			deposit_kinds = get_deposit_kinds_all();
			statuses = get_statuses();
			minerals = get_minerals_all();
			return make_response(render_template("add_deposit_site_type.html", 
				kinds = deposit_kinds,
				statuses = statuses,
				minerals = minerals,
				permissions = get_default_permissions(),
				error = u"Данная комбинация (месторождение/направление использования) уже существует"));

		query = """
			INSERT INTO deposits_sites_types(
				deposit_site_id, 
				type_group_id, 
				minerals_id, 
				amount_a_b_c1, 
				amount_c2, 
				status_id, 
				description, 
				resource_id)
			VALUES(
				%s, %s, %s, %s, %s, %s, %s,
				(SELECT id FROM resources WHERE name = %s)
			)
		""";
		g.cur.execute(query, [deposit_site_id, type_group_id, mineral_id, amount_a_b_c1, amount_c2, status_id, description, uuid]);
		g.db.commit();
		return make_response(redirect(url_for("deposits_sites_types")));

@app.route("/edit_deposit_site_type/", methods=["GET", "POST"])
def edit_deposit_site_type():
	if not ip_based_access_control(request.remote_addr, "192.168.0.0"):
		return redirect(url_for('denied'));
	if not is_valid_session(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if not is_admin(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if request.method == "GET":
		deposit_site_type_id = request.args.get("deposit_site_type_id", None);
		if not deposit_site_type_id:
			return make_response(redirect(url_for("deposits_sites_types")));
		resource_id = get_resource_id_for_deposit_site_type(deposit_site_type_id);
		query = """SELECT dst.id, m.name_ru AS mineral, 
					CONCAT(d.name_ru, " (", s.name_ru, ")") AS deposit_site, 
					dst.amount_a_b_c1, dst.amount_c2 
					FROM deposits_sites_types dst 
						INNER JOIN deposits_sites ds ON ds.id = dst.deposit_site_id 
						INNER JOIN deposits d ON d.id = ds.deposit_id 
						INNER JOIN sites s ON s.id = ds.site_id 
						INNER JOIN minerals m ON m.id=dst.minerals_id 
							WHERE dst.id=%s""";
		g.cur.execute(query, [deposit_site_type_id]);
		row = g.cur.fetchone();
		if not row:
			return make_response(redirect(url_for("deposits_sites_types")));
		return make_response(render_template("edit_deposit_site_type.html",
				permissions = get_permissions(resource_id), 
				deposit_site_type_id = deposit_site_type_id,
				deposit_site = row["deposit_site"],
				mineral = row["mineral"],
				amount_a_b_c1 = row["amount_a_b_c1"],
				amount_c2 = row["amount_c2"]
				));
	elif request.method == "POST":
		deposit_site_type_id = request.form.get("deposit_site_type_id", None);
		amount_a_b_c1 = request.form.get("amount_a_b_c1", None);
		amount_c2 = request.form.get("amount_c2", None);
		query = """SELECT dst.id, m.name_ru AS mineral, 
					CONCAT(d.name_ru, " (", s.name_ru, ")") AS deposit_site, 
					dst.amount_a_b_c1, dst.amount_c2 
					FROM deposits_sites_types dst 
						INNER JOIN deposits_sites ds ON ds.id = dst.deposit_site_id 
						INNER JOIN deposits d ON d.id = ds.deposit_id 
						INNER JOIN sites s ON s.id = ds.site_id 
						INNER JOIN minerals m ON m.id=dst.minerals_id 
							WHERE dst.id=%s""";
		g.cur.execute(query, [deposit_site_type_id]);
		row = g.cur.fetchone();
		if not row:
			return make_response(redirect(url_for("deposits_sites_types")));

		if not re.match("[0-9]+\\.?[0-9]*", amount_a_b_c1) or not re.match("[0-9]+\\.?[0-9]*", amount_c2) or float(amount_a_b_c1) < 0 or float(amount_c2) < 0:
			resource_id = get_resource_id_for_deposit_site_type(deposit_site_type_id);
			query = """SELECT dst.id, m.name_ru AS mineral, 
						CONCAT(d.name_ru, " (", s.name_ru, ")") AS deposit_site, 
						dst.amount_a_b_c1, dst.amount_c2 
						FROM deposits_sites_types dst 
							INNER JOIN deposits_sites ds ON ds.id = dst.deposit_site_id 
							INNER JOIN deposits d ON d.id = ds.deposit_id 
							INNER JOIN sites s ON s.id = ds.site_id 
							INNER JOIN minerals m ON m.id=dst.minerals_id 
								WHERE dst.id=%s""";
			g.cur.execute(query, [deposit_site_type_id]);
			row = g.cur.fetchone();
			if not row:
				return make_response(redirect(url_for("deposits_sites_types")));
			return make_response(render_template("edit_deposit_site_type.html",
					permissions = get_permissions(resource_id), 
					deposit_site_type_id = deposit_site_type_id,
					deposit_site = row["deposit_site"],
					mineral = row["mineral"],
					amount_a_b_c1 = row["amount_a_b_c1"],
					amount_c2 = row["amount_c2"],
					error = "Запас A+B+C1/C2 должены быть положительными значениями"
					));
		query = "UPDATE deposits_sites_types SET amount_a_b_c1 = %s, amount_c2 = %s WHERE id = %s";
		g.cur.execute(query, [amount_a_b_c1, amount_c2, deposit_site_type_id]);
		g.db.commit();
		return make_response(redirect(url_for("deposits_sites_types")));

@app.route("/deposits_sites_licences/", methods=["GET"])
def deposits_sites_licences():
	if not ip_based_access_control(request.remote_addr, "192.168.0.0"):
		return redirect(url_for('denied'));
	if not is_valid_session(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if not is_admin(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if request.method == "GET":
		dsl = get_deposits_sites_licenses();
		return make_response(render_template("deposits_sites_licenses.html", 
				deposits_sites_licenses = dsl,
				token = get_hash(request.cookies.get("token", None))
				));

@app.route("/delete_deposit_site_license/", methods=["GET"])
def delete_deposit_site_license():
	if not ip_based_access_control(request.remote_addr, "192.168.0.0"):
		return redirect(url_for('denied'));
	if not is_valid_session(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if not is_valid_hash(request.cookies.get("token", None), request.args.get("token", None)):
		return make_response(redirect(url_for("login")));
	if not is_admin(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if request.method == "GET":
		deposit_site_license_id = request.args.get("deposit_site_license_id", None);
		
		query = "SELECT deposit_site_type_id, amount_a_b_c1, amount_c2 FROM deposits_sites_licenses WHERE id = %s";
		g.cur.execute(query, [deposit_site_license_id]);
		row = g.cur.fetchone();

		amount_a_b_c1 = row["amount_a_b_c1"];
		amount_c2 = row["amount_c2"];
		deposit_site_type_id = row["deposit_site_type_id"];

		query = "UPDATE deposits_sites_types SET amount_a_b_c1 = amount_a_b_c1 + %s, amount_c2 = amount_c2 + %s WHERE id = %s";
		g.cur.execute(query, [amount_a_b_c1, amount_c2, deposit_site_type_id]);
		g.db.commit();

		query = """
			DELETE FROM resources 
				WHERE id = (SELECT resource_id FROM deposits_sites_licenses WHERE id = %s)
		""";
		g.cur.execute(query, [deposit_site_license_id]);
		g.db.commit();
		return make_response(redirect(url_for("deposits_sites_licences")));

@app.route("/get_licenses_ajax/", methods=["GET"])
def get_licenses_ajax():
	if not ip_based_access_control(request.remote_addr, "192.168.0.0"):
		return jsonify([]);
	if not is_valid_session(request.cookies.get("token", None)):
		return jsonify([]);
	if not is_admin(request.cookies.get("token", None)):
		return jsonify([]);
	if request.method == "GET":
		partial_license = request.args.get("partial_license", "");
		return jsonify(get_licenses_by_name(partial_license));
	else:
		return jsonify([]);

@app.route("/get_deposit_site_type_ajax/", methods=["GET"])
def get_deposit_site_type_ajax():
	if not ip_based_access_control(request.remote_addr, "192.168.0.0"):
		return jsonify([]);
	if not is_valid_session(request.cookies.get("token", None)):
		return jsonify([]);
	if not is_admin(request.cookies.get("token", None)):
		return jsonify([]);
	if request.method == "GET":
		partial_name = request.args.get("partial_name", "");
		return jsonify(get_deposits_sites_types_by_name(partial_name));
	else:
		return jsonify([]);

@app.route("/add_deposit_site_license/", methods=["GET", "POST"])
def add_deposit_site_license():
	if not ip_based_access_control(request.remote_addr, "192.168.0.0"):
		return redirect(url_for('denied'));
	if not is_valid_session(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if not is_admin(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if request.method == "GET":
		return make_response(render_template("add_deposit_site_license.html", 
			permissions = get_default_permissions()));
	elif request.method == "POST":
		license_id = request.form.get("license_id", None);
		deposit_site_type_id = request.form.get("deposit_site_type_id", None);
		amount_a_b_c1 = request.form.get("amount_a_b_c1", None);
		amount_c2 = request.form.get("amount_c2", None);

		if not license_id:
			return make_response(render_template("add_deposit_site_license.html", 
				permissions = get_default_permissions(),
				error = u"Неверная лицензия"));
		if not deposit_site_type_id:
			return make_response(render_template("add_deposit_site_license.html", 
				permissions = get_default_permissions(),
				error = u"Неверный код для комбинации (месторождение/участок/направление использования)"));

		roles = get_roles();
		permitted_roles = get_roles_from_form(request.form, roles);
		uuid = get_uuid();
		add_resource(uuid);
		add_read_permissions(permitted_roles, uuid);

		query = "SELECT * FROM licenses WHERE id = %s";
		g.cur.execute(query, [license_id]);
		row = g.cur.fetchone();
		if not row:
			return make_response(render_template("add_deposit_site_license.html", 
				permissions = get_default_permissions(),
				error = u"Неверная лицензия"));

		query = "SELECT * FROM deposits_sites_types WHERE id = %s";
		g.cur.execute(query, [deposit_site_type_id]);
		row = g.cur.fetchone();
		if not row:
			return make_response(render_template("add_deposit_site_license.html", 
				permissions = get_default_permissions(),
				error = u"Неверный код для комбинации (месторождение/участок/направление использования)"));

		query = """
			SELECT amount_a_b_c1 - %s AS remainder_a_b_c1 FROM deposits_sites_types 
				WHERE id = %s
		""";

		g.cur.execute(query, [amount_a_b_c1, deposit_site_type_id]);
		row = g.cur.fetchone();
		if not row:
			return make_response(render_template("add_deposit_site_license.html", 
				permissions = get_default_permissions(),
				error = u"Неверный код связи"));
		if row["remainder_a_b_c1"] < 0:
			return make_response(render_template("add_deposit_site_license.html", 
				permissions = get_default_permissions(),
				error = u"Недостаточный запас A+B+C1 на балансе"));

		query = """
			SELECT amount_c2 - %s AS remainder_c2 FROM deposits_sites_types 
				WHERE id = %s
		""";

		g.cur.execute(query, [amount_c2, deposit_site_type_id]);
		row = g.cur.fetchone();
		if not row:
			return make_response(render_template("add_deposit_site_license.html", 
				permissions = get_default_permissions(),
				error = u"Неверный код связи"));
		if row["remainder_c2"] < 0:
			return make_response(render_template("add_deposit_site_license.html", 
				permissions = get_default_permissions(),
				error = u"Недостаточный запас C2 на балансе"));

		query = """
			UPDATE deposits_sites_types SET amount_a_b_c1 = amount_a_b_c1 - %s, amount_c2 = amount_c2 - %s WHERE id = %s
		"""
		g.cur.execute(query, [amount_a_b_c1, amount_c2, deposit_site_type_id]);
		g.db.commit();

		query = """
			INSERT INTO deposits_sites_licenses(
				deposit_site_type_id, 
				license_id, 
				amount_a_b_c1, 
				amount_c2, 
				resource_id)
			VALUES(
				%s, %s, %s, %s,
				(SELECT id FROM resources WHERE name = %s)
			)
		""";
		g.cur.execute(query, [deposit_site_type_id, license_id, amount_a_b_c1, amount_c2, uuid]);
		g.db.commit();
		return make_response(redirect(url_for("deposits_sites_licences")));

@app.route("/deposits_sites_contours/", methods=["GET"])
def deposits_sites_contours():
	if not ip_based_access_control(request.remote_addr, "192.168.0.0"):
		return redirect(url_for('denied'));
	if not is_valid_session(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if not is_admin(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if request.method == "GET":
		dsc = get_deposits_sites_contours();
		return make_response(render_template("deposits_sites_contours.html", 
				deposits_sites_contours = dsc,
				token = get_hash(request.cookies.get("token", None))
				));

@app.route("/add_deposit_site_contour/", methods=["GET", "POST"])
def add_deposit_site_contour():
	if not ip_based_access_control(request.remote_addr, "192.168.0.0"):
		return redirect(url_for('denied'));
	if not is_valid_session(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if not is_admin(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if request.method == "GET":
		return render_template("add_deposit_site_contour.html", 
			permissions = get_default_permissions(), 
			error = None);
	elif request.method == "POST":
		deposit_site_type_id = request.form.get("deposit_site_type_id", None);
		points = request.form.getlist("point_number", None);
		lats = request.form.getlist("lat", None);
		lons = request.form.getlist("lon", None);
		if len(points) != len(lons) or len(points) != len(lats):
			return render_template("add_deposit_site_contour.html", 
				permissions = get_default_permissions(), 
				error = u"Неверное количество точек");
		for i in range(0, len(points)):
			if not re.match("[0-9]+", points[i]):
				return render_template("add_deposit_site_contour.html", 
					permissions = get_default_permissions(), 
					error = u"Неверный номер точки");
			if not re.match("[0-9]+\.[0-9]+", lats[i]):
				return render_template("add_deposit_site_contour.html", 
					permissions = get_default_permissions(), 
					error = u"Неверное значение для широты");
			if not re.match("[0-9]+\.[0-9]+", lons[i]):
				return render_template("add_deposit_site_contour.html", 
					permissions = get_default_permissions(), 
					error = u"Неверное значение для долготы");
		query = "SELECT * FROM deposits_sites_types WHERE id = %s";
		g.cur.execute(query, [deposit_site_type_id]);
		row = g.cur.fetchone();
		if not row:
			return render_template("add_deposit_site_contour.html", 
				permissions = get_default_permissions(), 
				error = u"Неверное идентификатор месторождения/участок/ПИ");
		query = "SELECT * FROM deposit_site_contours WHERE deposit_site_type_id = %s";
		g.cur.execute(query, [deposit_site_type_id]);
		row = g.cur.fetchone();
		if row:
			return render_template("add_deposit_site_contour.html", 
				permissions = get_default_permissions(), 
				error = u"Контур уже существует");
		query = "DELETE FROM deposit_site_contours WHERE deposit_site_type_id = %s";
		g.cur.execute(query, [deposit_site_type_id]);
		for i in range(0, len(points)):
			roles = get_roles();
			permitted_roles = get_roles_from_form(request.form, roles);
			uuid = get_uuid();
			add_resource(uuid);
			add_read_permissions(permitted_roles, uuid);
			query = """
				INSERT INTO deposit_site_contours(
					deposit_site_type_id, 
					latitude, 
					longitude, 
					point_number, 
					resource_id)
				VALUES(
					%s, %s, %s, %s,
					(SELECT id FROM resources WHERE name = %s)
				)
			""";
			g.cur.execute(query, [deposit_site_type_id, lats[i], lons[i], points[i], uuid]);
			g.db.commit();
		return make_response(redirect(url_for("deposits_sites_contours")));

@app.route("/delete_deposit_site_contour/", methods=["GET"])
def delete_deposit_site_contour():
	if not ip_based_access_control(request.remote_addr, "192.168.0.0"):
		return redirect(url_for('denied'));
	if not is_valid_session(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if not is_valid_hash(request.cookies.get("token", None), request.args.get("token", None)):
		return make_response(redirect(url_for("login")));
	if not is_admin(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if request.method == "GET":
		deposit_site_type_id = request.args.get("deposit_site_type_id", None);

		query = """
			DELETE FROM resources 
				WHERE id IN (SELECT resource_id FROM deposit_site_contours WHERE deposit_site_type_id = %s)
		""";
		g.cur.execute(query, [deposit_site_type_id]);
		g.db.commit();
		return make_response(redirect(url_for("deposits_sites_contours")));

@app.route("/pending_registrations/")
def pending_registrations():
	if not ip_based_access_control(request.remote_addr, "192.168.0.0"):
		return redirect(url_for('denied'));
	if not is_valid_session(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if not is_admin(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	query = "SELECT id, user_first_name, user_last_name, phone_number, email_address, description FROM pending_registrations";
	g.cur.execute(query);
	rows = g.cur.fetchall();
	pending_registrations = [];
	for row in rows:
		pending_registrations.append({
			"registration_id": row["id"],
			"first_name": row["user_first_name"],
			"last_name": row["user_last_name"],
			"phone_number": row["phone_number"],
			"email_address": row["email_address"],
			"description": row["description"],
		});
	return render_template("pending_registrations.html", 
		pending_registrations = pending_registrations,
		token = get_hash(request.cookies.get("token", None)));

@app.route("/delete_pending_registration/", methods=["GET"])
def delete_pending_registration():
	if not ip_based_access_control(request.remote_addr, "192.168.0.0"):
		return redirect(url_for('denied'));
	if not is_valid_session(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if not is_valid_hash(request.cookies.get("token", None), request.args.get("token", None)):
		return make_response(redirect(url_for("login")));
	if not is_admin(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if request.method == "GET":
		registration_id = request.args.get("registration_id", None);

		query = """
			DELETE FROM pending_registrations WHERE id = %s
		""";
		g.cur.execute(query, [registration_id]);
		g.db.commit();
		return make_response(redirect(url_for("pending_registrations")));

@app.route("/users/")
def users():
	if not ip_based_access_control(request.remote_addr, "192.168.0.0"):
		return redirect(url_for('denied'));
	if not is_valid_session(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if not is_admin(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	query = """SELECT u.id, u.user_first_name, u.user_last_name, 
		u.phone_number, u.email_address, u.enabled, 
		u.username, r.role 
		FROM users u 
		INNER JOIN roles r ON u.role_id = r.id;
		""";
	g.cur.execute(query);
	rows = g.cur.fetchall();
	users = [];
	for row in rows:
		users.append({
			"user_id": row["id"],
			"user_first_name": row["user_first_name"],
			"user_last_name": row["user_last_name"],
			"phone_number": row["phone_number"],
			"email_address": row["email_address"],
			"enabled": row["enabled"],
			"username": row["username"],
			"role": row["role"]
		});
	return render_template("users.html", 
		users = users,
		token = get_hash(request.cookies.get("token", None)));

@app.route("/edit_user/", methods=["GET", "POST"])
def edit_user():
	if not ip_based_access_control(request.remote_addr, "192.168.0.0"):
		return redirect(url_for('denied'));
	if not is_valid_session(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if not is_admin(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if request.method == "GET":
		user_id = request.args.get("user_id", None);
		if not user_id:
			return make_response(redirect(url_for("users")));

		query = """
			SELECT u.id AS user_id, u.user_first_name, u.user_last_name, 
			u.phone_number, u.email_address, u.enabled, 
			u.username, r.id AS role_id 
			FROM users u 
			INNER JOIN roles r ON u.role_id = r.id
			WHERE u.id = %s;
		""";
		g.cur.execute(query, [user_id]);
		row = g.cur.fetchone();
		if not row:
			return make_response(redirect(url_for("users")));
		user = row;

		role_id = row["role_id"];
		query = "SELECT id, role FROM roles";
		g.cur.execute(query);
		rows = g.cur.fetchall();
		roles = [];
		for row in rows:
			if row["id"] == role_id:
				roles.append({
					"role_id": row["id"],
					"role": row["role"]
					});
				break;
		for row in rows:
			if row["id"] != role_id:
				roles.append({
					"role_id": row["id"],
					"role": row["role"]
					});
		
		return make_response(render_template("edit_user.html",
				roles = roles,
				user = user
				));
	elif request.method == "POST":
		user_id = request.form.get("user_id", None);
		username = request.form.get("username", None);
		user_first_name = request.form.get("user_first_name", None);
		user_last_name = request.form.get("user_last_name", None);
		phone_number = request.form.get("phone_number", None);
		email_address = request.form.get("email_address", None);
		enabled = request.form.get("enabled", False);
		if enabled == "on":
			enabled = True;
		role_id = request.form.get("role", None);
		if not re.match("[0-9]+", user_id):
			return make_response(redirect(url_for("users")));
		if not re.match("[0-9]+", role_id):
			return make_response(redirect(url_for("users")));
		
		if not user_id:
			return make_response(redirect(url_for("users")));

		query = """
			SELECT u.id AS user_id, u.user_first_name, u.user_last_name, 
			u.phone_number, u.email_address, u.enabled, 
			u.username, r.id AS role_id 
			FROM users u 
			INNER JOIN roles r ON u.role_id = r.id
			WHERE u.id = %s;
		""";
		g.cur.execute(query, [user_id]);
		row = g.cur.fetchone();
		if not row:
			return make_response(redirect(url_for("users")));
		user = row;

		role_id = row["role_id"];
		query = "SELECT id, role FROM roles";
		g.cur.execute(query);
		rows = g.cur.fetchall();
		roles = [];
		for row in rows:
			if row["id"] == role_id:
				roles.append({
					"role_id": row["id"],
					"role": row["role"]
					});
				break;
		for row in rows:
			if row["id"] != role_id:
				roles.append({
					"role_id": row["id"],
					"role": row["role"]
					});
		if not re.match("^[A-Z]{1}[a-z]{1,99}$", user_first_name):
			return make_response(render_template("edit_user.html",
				roles = roles,
				user = user,
				error = u"Имя является обязательным полем"
				));
		if not re.match("^[A-Z]{1}[a-z]{1,99}$", user_last_name):
			return make_response(render_template("edit_user.html",
				roles = roles,
				user = user,
				error = u"Фамилия является обязательным полем"
				));
		role_id = request.form.get("role", None);
		if not re.match("[0-9]+", role_id):
			return make_response(redirect(url_for("users")));
		query = """
			UPDATE users SET user_first_name = %s,
				user_last_name = %s,
				phone_number = %s,
				role_id = %s,
				enabled = %s
				WHERE id = %s
		""";
		g.cur.execute(query, [user_first_name, user_last_name, phone_number, role_id, enabled, user_id])
		g.db.commit();

		return make_response(redirect(url_for("users")));

@app.route("/add_user/", methods=["GET", "POST"])
def add_user():
	if not ip_based_access_control(request.remote_addr, "192.168.0.0"):
		return redirect(url_for('denied'));
	if not is_valid_session(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if not is_admin(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if request.method == "GET":
		query = "SELECT id, role FROM roles";
		g.cur.execute(query);
		rows = g.cur.fetchall();
		roles = [];
		for row in rows:
			roles.append({
				"role_id": row["id"],
				"role": row["role"]
			});
		return make_response(render_template("add_user.html",
				roles = roles,
				));
	elif request.method == "POST":
		username = request.form.get("username", None);
		user_first_name = request.form.get("user_first_name", None);
		user_last_name = request.form.get("user_last_name", None);
		phone_number = request.form.get("phone_number", None);
		password = request.form.get("password", None);
		email_address = request.form.get("email_address", None);
		enabled = request.form.get("enabled", False);
		if enabled == "on":
			enabled = True;
		else: 
			enabled = False;
		query = "SELECT id, role FROM roles";
		g.cur.execute(query);
		rows = g.cur.fetchall();
		roles = [];
		for row in rows:
			roles.append({
				"role_id": row["id"],
				"role": row["role"]
			});
		query = "SELECT * FROM users WHERE username LIKE %s OR email_address LIKE %s";
		g.cur.execute(query, [username, email_address]);
		rows = g.cur.fetchall();
		if len(rows) > 0:
			return make_response(render_template("add_user.html",
				roles = roles,
				error = u"Пользователь уже существует"
				));
		role_id = request.form.get("role", None);
		if not re.match("[0-9]+", role_id):
			return make_response(redirect(url_for("users")));
		if not re.match("^[A-Z]{1}[a-z]{1,99}$", user_first_name):
			return make_response(render_template("add_user.html",
				roles = roles,
				error = u"Имя является обязательным полем"
				));
		if not re.match("^[A-Z]{1}[a-z]{1,99}$", user_last_name):
			return make_response(render_template("add_user.html",
				roles = roles,
				error = u"Фамилия является обязательным полем"
				));
		if not re.match("^[a-z0-9]{4,100}$", username):
			return make_response(render_template("add_user.html",
				roles = roles,
				error = u"Неверное имя пользователя"
				));
		if not re.match("^(?=.*[A-Z]+)(?=.*[a-z]+)(?=.*[0-9]+)(?=.*[$#%]+)", password) or \
			not re.match("^[a-zA-Z0-9#$%&@]{10,100}$", password):
			return make_response(render_template("add_user.html",
				roles = roles,
				error = u"Неверный пароль"
				));
		if not re.match("^[a-zA-Z0-9._-]+@[a-zA-Z]+\.[a-zA-Z]{2,3}$", email_address):
			return make_response(render_template("add_user.html",
				roles = roles,
				error = u"Неверный адрес электронной почты"
				));
		query = """
			INSERT INTO geomap.users (user_first_name, 
				user_last_name, 
				phone_number, 
				email_address, 
				username, 
				password, 
				role_id, 
				enabled) 
				VALUES(%s, %s, %s, %s, %s, SHA2(CONCAT(%s, %s), 256), %s, %s);
		""";
		g.cur.execute(query, [user_first_name, user_last_name, phone_number, email_address, username, password, config["PASSWORD_SALT"], role_id, enabled]);
		g.db.commit();
		return make_response(redirect(url_for("users")));

@app.route("/delete_user/", methods=["GET"])
def delete_user():
	if not ip_based_access_control(request.remote_addr, "192.168.0.0"):
		return redirect(url_for('denied'));
	if not is_valid_session(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	"""
	If user is admin, then he/she can delete, create and modify all records already
	"""
	if not is_admin(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if not is_valid_hash(request.cookies.get("token", None), request.args.get("token", None)):
		return make_response(redirect(url_for("login")));
	#role_id = Token.get_role_id(Token.decode(request.cookies.get("token", None)));
	user_id = request.args.get("user_id", None);
	query = """
		DELETE FROM users 
			WHERE id = 
				%s
		""";
	g.cur.execute(query, [int(user_id)]);
	g.db.commit();
	return make_response(redirect(url_for("users")));

@app.route("/investments/")
def investments():
	if not ip_based_access_control(request.remote_addr, "192.168.0.0"):
		return redirect(url_for('denied'));
	if not is_valid_session(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if not is_admin(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	query = """
		SELECT i.id, d.name_ru AS deposit, s.name_ru AS site, m.name_ru AS mineral, i.area_ha
		FROM investments i 
		INNER JOIN deposits_sites ds ON ds.id = i.deposit_site_id
		INNER JOIN minerals m ON m.id = i.mineral_id
		INNER JOIN deposits d ON d.id = ds.deposit_id
		INNER JOIN sites s ON s.id = ds.site_id
		"""
	investments = [];
	g.cur.execute(query, []);
	rows = g.cur.fetchall();
	for row in rows:
		investments.append({
			"id": row["id"],
			"deposit": row["deposit"],
			"site": row["site"],
			"mineral": row["mineral"],
			"area_ha": row["area_ha"]
			});
	return make_response(render_template("investments.html", investments = investments, token = get_hash(request.cookies.get("token", None))));

@app.route("/add_investment/", methods=["GET", "POST"])
def add_investment():
	if not ip_based_access_control(request.remote_addr, "192.168.0.0"):
		return redirect(url_for('denied'));
	if not is_valid_session(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if not is_admin(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if request.method == "GET":
		return make_response(render_template("add_investment.html", permissions = get_default_permissions()));
	else:
		deposit_site_id = request.form.get("deposit_site_id", None);
		mineral_id = request.form.get("mineral_id", None);
		area_ha = request.form.get("area_ha", None);
		external_url = request.form.get("external_url", None);

		presentation = request.files["presentation"];
		description = request.files["description"];
		
		query = "SELECT * FROM minerals WHERE id = %s";
		g.cur.execute(query, [mineral_id]);
		rows = g.cur.fetchall();
		print(g.cur._last_executed);

		if len(rows) != 1:
			return make_response(render_template("add_investment.html", permissions = get_default_permissions(), error = u"Неверное значение полезного ископаемого"));

		query = "SELECT * FROM deposits_sites WHERE id = %s";
		g.cur.execute(query, [deposit_site_id]);
		rows = g.cur.fetchall();

		if len(rows) != 1:
			return make_response(render_template("add_investment.html", permissions = get_default_permissions(), error = u"Неверное значение месторождения"));

		if not re.match("^[0-9]*\.?[0-9]+", area_ha):
			return make_response(render_template("add_investment.html", permissions = get_default_permissions(), error = u"Неверное значение для площади"));

		uuid = get_uuid();
		
		roles = get_roles();
		permitted_roles = get_roles_from_form(request.form, roles);
		
		add_resource(uuid);
		add_read_permissions(permitted_roles, uuid);

		presentation_uuid = get_uuid();
		description_uuid = get_uuid();

		if presentation:
			fh = open(config["FILE_STORAGE_DIR"] + "/" + presentation_uuid + ".pdf", "w+");
			fh.write(presentation.read());
			fh.close();

		if description:
			fh = open(config["FILE_STORAGE_DIR"] + "/" + description_uuid + ".pdf", "w+");
			fh.write(description.read());
			fh.close();

		query = """
			INSERT INTO investments(
				deposit_site_id, 
				mineral_id, 
				area_ha, 
				presentation_url_ru,
				description_url_ru, 
				external_url,
				resource_id)
			VALUES(
				%s, %s, %s, %s, %s, %s,
				(SELECT id FROM resources WHERE name = %s)
			)
		""";
		g.cur.execute(query, [deposit_site_id, mineral_id, area_ha, presentation_uuid + ".pdf", description_uuid + ".pdf", external_url, uuid]);
		g.db.commit();
		return make_response(redirect(url_for("investments")));

@app.route("/edit_investment/", methods=["GET", "POST"])
def edit_investment():
	if not ip_based_access_control(request.remote_addr, "192.168.0.0"):
		return redirect(url_for('denied'));
	if not is_valid_session(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if not is_admin(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if request.method == "GET":
		investment_id = request.args.get("investment_id", None);
		resource_id = get_resource_id_for_investment(investment_id);
		query = """
			SELECT CONCAT(d.name_ru, ' ', s.name_ru) AS deposit, 
				m.name_ru AS mineral, 
				i.area_ha, i.external_url, i.resource_id, i.id
				FROM investments i 
				INNER JOIN deposits_sites ds ON ds.id = i.deposit_site_id
				INNER JOIN deposits d ON d.id = ds.deposit_id
				INNER JOIN sites s ON s.id = ds.site_id
				INNER JOIN minerals m ON m.id = i.mineral_id
				WHERE i.id = %s
		""";
		g.cur.execute(query, [investment_id]);
		row = g.cur.fetchone();
		if not row:
			return make_response(redirect(url_for("investments")));
		return make_response(render_template("edit_investment.html",
				permissions = get_permissions(resource_id), 
				investment_id = investment_id,
				deposit = row["deposit"],
				mineral = row["mineral"],
				area_ha = row["area_ha"],
				external_url = row["external_url"]
				));
	else:
		investment_id = request.form.get("investment_id", None);
		area_ha = request.form.get("area_ha", None);
		external_url = request.form.get("external_url", None);

		if not re.match("^[0-9]*\.?[0-9]+", area_ha):
			resource_id = get_resource_id_for_investment(investment_id);
			query = """
				SELECT CONCAT(d.name_ru, ' ', s.name_ru) AS deposit, 
					m.name_ru AS mineral, 
					i.area_ha, i.external_url, i.resource_id, i.id
					FROM investments i 
					INNER JOIN deposits_sites ds ON ds.id = i.deposit_site_id
					INNER JOIN deposits d ON d.id = ds.deposit_id
					INNER JOIN sites s ON s.id = ds.site_id
					INNER JOIN minerals m ON m.id = i.mineral_id
					WHERE i.id = %s
			""";
			g.cur.execute(query, [investment_id]);
			row = g.cur.fetchone();
			if not row:
				return make_response(redirect(url_for("investments")));
			return make_response(render_template("edit_investment.html",
					permissions = get_permissions(resource_id), 
					investment_id = investment_id,
					deposit = row["deposit"],
					mineral = row["mineral"],
					area_ha = row["area_ha"],
					external_url = row["external_url"],
					error = u"Неверное значение для площади"
					));

		query = "UPDATE investments SET area_ha = %s, external_url = %s WHERE id = %s";
		g.cur.execute(query, [area_ha, external_url, investment_id]);
		g.db.commit();

		presentation = request.files["presentation"];
		description = request.files["description"];

		presentation_uuid = get_uuid();
		description_uuid = get_uuid();

		if presentation:
			fh = open(config["FILE_STORAGE_DIR"] + "/" + presentation_uuid + ".pdf", "w+");
			fh.write(presentation.read());
			fh.close();
			
			query = "UPDATE investments SET presentation_url_ru = %s WHERE id = %s";
			g.cur.execute(query, [presentation_uuid + ".pdf", investment_id]);
			g.db.commit();

		if description:
			fh = open(config["FILE_STORAGE_DIR"] + "/" + description_uuid + ".pdf", "w+");
			fh.write(description.read());
			fh.close();

			query = "UPDATE investments SET description_url_ru = %s WHERE id = %s";
			g.cur.execute(query, [description_uuid + ".pdf", investment_id]);
			g.db.commit();

		return make_response(redirect(url_for("investments")));


@app.route("/delete_investment/")
def delete_investment():
	if not ip_based_access_control(request.remote_addr, "192.168.0.0"):
		return redirect(url_for('denied'));
	if not is_valid_session(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if not is_admin(request.cookies.get("token", None)):
		return make_response(redirect(url_for("login")));
	if not is_valid_hash(request.cookies.get("token", None), request.args.get("token", None)):
		return make_response(redirect(url_for("login")));
	investment_id = request.args.get("investment_id", None);
	query = """
			DELETE FROM resources 
				WHERE id = (SELECT resource_id FROM investments WHERE id = %s)
		""";
	g.cur.execute(query, [investment_id]);
	g.db.commit();
	return make_response(redirect(url_for("investments")));

if __name__ == "__main__":
	app.run(port = 5002, host="0.0.0.0");
