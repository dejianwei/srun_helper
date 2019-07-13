#!/usr/env/python python
# _*_ coding: utf-8 _*_

import sys
import requests
import socket
import time
import json
import base64
import hmac
import hashlib

user_name = '3120181045'
password = '****'

host_url = 'http://10.0.0.55/cgi-bin/srun_portal'
challenge_url = 'http://10.0.0.55/cgi-bin/get_challenge'

def login():
	rsp_json = get_challenge()
	data = {
		'username': user_name,
		'action': 'login',
		'n': '200',
		'type': '1',
		'ac_id': '1',
		'callback': get_callback(),
		'ip': rsp_json['client_ip']
	}
	usr_data = {
		'username':user_name, 
		'password':password, 
		'ip':rsp_json['client_ip'], 
		'acid': data['ac_id'], 
		'enc_ver':'srun_bx1'
	}
	token = rsp_json['challenge']

	# base64编码
	x_encode_res = xencode(json.dumps(usr_data, separators=(',', ':')), token)
	mapping = dict(zip("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=",
			"LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA="))
	b64_res = base64.b64encode(
	bytes([ord(s) for s in x_encode_res])).decode()
	base64_encode_res = ''.join([mapping[b] for b in b64_res])
	data['info'] = '{SRBX1}' + base64_encode_res

	# 深澜的bug，这里不用密码也OK
	# hmd5 = hmac.new(bytes(token, 'utf-8'), bytes(password, 'utf-8'), digestmod='MD5').hexdigest()
	hmd5 = hmac.new(bytes(token, 'utf-8'), bytes('', 'utf-8'), digestmod='MD5').hexdigest()
	data['password'] = '{MD5}' + hmd5

	checksum = bytes(token+user_name+token+hmd5+token+data['ac_id']+token+rsp_json['client_ip']+token+data['n']+token+data['type']+token+data['info'], 'utf-8')
	data['chksum'] = hashlib.sha1(checksum).hexdigest()

	rsp = requests.get(host_url, params=data)
	rsp_msg = json.loads(rsp.text.split('(')[1][0:-1])
	print(rsp_msg['error'])

def logout():
	data = {
		'action': "logout",
		'username': user_name,
		'ac_id':1, 
		'ip': '' 
	}
	rsp = requests.get(host_url, params=data)
	print(rsp.text)

def get_challenge():
	data = {
	'callback': get_callback(),
	'username': user_name
	}
	rsp = requests.get(challenge_url, params=data)
	rsp_json = json.loads(rsp.text.split('(')[1].split(')')[0])
	return rsp_json

def get_callback():
	return 'jsonp' + str(int(time.time()*1000))
	
def xencode(msg: str, key):
	def char_code_at(stri, index):
		return 0 if index >= len(stri) else ord(stri[index])

	def s(a: str, b: bool):
		c = len(a)
		v = []
		for i in range(0, c, 4):
			v.append(char_code_at(a, i) | (char_code_at(a, i+1) << 8) |
				(char_code_at(a, i+2) << 16) | (char_code_at(a, i+3) << 24))
		if b:
			v.append(c)
		return v

	def l(a, b):
		d = len(a)
		c = (d-1) << 2
		if b:
			m = a[d-1]
			if (m < c-3) or (m > c):
				return None
			c = m
		for i in range(0, d):
			a[i] = ''.join([chr(a[i] & 0xff), chr((a[i] >> 8) & 0xff), chr(
				(a[i] >> 16) & 0xff), chr((a[i] >> 24) & 0xff)])
		if b:
			return (''.join(a))[0:c]
		else:
			return ''.join(a)

	if msg == "":
		return ""
	v = s(msg, True)
	k = s(key, False)
	n = len(v) - 1
	z = v[n]
	y = v[0]
	c = 0x86014019 | 0x183639A0
	m = e = p = d = 0
	q = 6 + 52 // (n + 1)
	while 0 < q:
		q -= 1
		d = d + c & (0x8CE0D9BF | 0x731F2640)
		e = d >> 2 & 3
		for p in range(0, n):
			y = v[p+1]
			m = z >> 5 ^ y << 2
			m += (y >> 3 ^ z << 4) ^ (d ^ y)
			m += k[(p & 3) ^ e] ^ z
			z = v[p] = v[p] + m & (0xEFB8D130 | 0x10472ECF)
		y = v[0]
		m = z >> 5 ^ y << 2
		m += (y >> 3 ^ z << 4) ^ (d ^ y)
		m += k[(n & 3) ^ e] ^ z
		z = v[n] = v[n] + m & (0xBB390742 | 0x44C6F8BD)
	return l(v, False)


if __name__=='__main__':
	cmd = sys.argv[1]
	if cmd == 'login':
		login()
	elif cmd == 'logout':
		logout()
	else:
		print('输入错误.')
