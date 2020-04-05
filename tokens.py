# -*- coding: utf-8 -*-
import json
import time
from config import config
from scrypto import AESCipher

cipher = AESCipher(config["MASTER_SECRET"]);
nonce = config["SERVER_NONCE"];

class Token:
	@staticmethod
	def is_valid(token):
		try:
			if not token:
				return False
			if token["server_nonce"] != nonce:
				return False
			now = int(time.mktime(time.gmtime()))
			return now <= token["valid_until"];
		except:
			return False

	@staticmethod
	def get_token_hash(token):
		try:
			return token["token"];
		except:
			return ""

	@staticmethod
	def get_user_id(token):
		if not token:
			return None
		if Token.is_valid(token):
			return token["user_id"];
		return None

	@staticmethod
	def get_role_id(token):
		if not token:
			return None
		if Token.is_valid(token):
			return token["role_id"];
		return None

	@staticmethod
	def decode(token):
		try:
			token = cipher.decrypt(token);
			return json.loads(token);
		except:
			return None

	@staticmethod
	def encode(role_id, user_id, hased_token, server_nonce, expires_in):
		# Hash based token is redundant here
		now = int(time.mktime(time.gmtime()))
		valid_until = now + expires_in;
		token = json.dumps({
			"token": hased_token,
			"valid_until": valid_until,
			"role_id": role_id,
			"user_id": user_id,
			"server_nonce": server_nonce
			});
		return cipher.encrypt(token);