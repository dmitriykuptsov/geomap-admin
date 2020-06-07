from flask import jsonify
from tokens import Token
import binascii
import os
import re

class Utils():
	DEFAULT_ENTROPY = 128
	@staticmethod
	def make_response(data, status_code):
		response = jsonify(data);
		response.status_code = status_code;
		return response

	@staticmethod
	def get_token(cookie):
		token = Token.decode(cookie);
		if Token.is_valid(token):
			return token;
		return None

	@staticmethod
	def token_hex(nbytes=None):
		if nbytes is None:
			nbytes = Utils.DEFAULT_ENTROPY
		random_bytes = os.urandom(nbytes)
		return binascii.hexlify(random_bytes).decode('ascii')

	@staticmethod
	def ip_to_int(ip):
		parts = ip.split(".");
		return (int(parts[3]) << 24) | (int(parts[2]) << 16) | (int(parts[1]) << 8) | (int(parts[0]));

	@staticmethod
	def is_ip_in_the_same_subnet(ip, subnet):
		ip = Utils.ip_to_int(ip);
		subnet = Utils.ip_to_int(subnet);
		return ((ip | subnet) == subnet);

	@staticmethod
	def is_valid_password(password):
		return (re.match("^(?=.*[A-Z]+)(?=.*[a-z]+)(?=.*[0-9]+)(?=.*[$#%]+)", password) and
		not re.match("^[a-zA-Z0-9#$%&@]{10,100}$", password))
