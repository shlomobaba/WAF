#!/usr/bin/env python3
import json
from http.server import BaseHTTPRequestHandler,HTTPServer
import argparse, os, random, sys, requests
from http.cookies import SimpleCookie
from socketserver import ThreadingMixIn
import checker
import threading
from urllib.parse import unquote
from riskLevel import riskLevel
import base64
import binascii
import urllib.parse
import sqlite_database
import re
import sqlite_database
import threading


hostname = "127.0.0.1:8080"
global counter
RE_BASE64 = "^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)?$"
counter=0
brute_force_shut_down = False

def get_banned_users():
    banned_users = db.select_query('BannedIp','IP')
    return [item for t in banned_users for item in t]

def check_for_banned_user(ip):
    banned_users = get_banned_users()
    for user in banned_users:
        if user is ip:
            return True
    return False

def merge_two_dicts(x, y):
    x.update(y)
    return x

def set_header():
    headers = {
        'Host': "127.0.0.1"
    }
    return headers

def check_for_too_much_requests(ip):
    number_of_requests = db.select_query('PacketsPerMinute','PPM','IP = '+ip)[0][0]
    if number_of_requests > 20:
        return True
    return False

def checkForBase64(potentialAttack):
    for attack in potentialAttack:
        if  isBase64(attack)== True:
            return True
    return False
'''
This function checks if the characters "=" and ":" in the user's request are part of the base64 encoding or they can be ignored
input:the user's request
output: the new formatted string (if it is not part of the base64 encoding the string will be without "=" and ":")
'''
def join_to_one_string(potentialAttack):

    if (checkForBase64(potentialAttack)==False):
        potentialAttack = "=".join(potentialAttack)
        potentialAttack = potentialAttack.split(":")
        if (checkForBase64(potentialAttack) == False):
            potentialAttack = ":".join(potentialAttack)
            potentialAttack=potentialAttack.split("\n")
            if(checkForBase64(potentialAttack)==False):
                potentialAttack="\n".join(potentialAttack)
    return potentialAttack

class ProxyHTTPRequestHandler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.0'
    session = requests.Session()

    def add_to_request_count(self):
        ip = self.client_address[0]
        if(ip in db.PacketsPerMinute):
            db.PacketsPerMinute[ip]+=1
        else:
            db.PacketsPerMinute[ip] = 1

    def do_HEAD(self):
        self.do_GET(body=False)
        return

    '''
    This function is responsible to send an answer to all "GET" requests
    input:the "ProxyHTTPRequestHandler" object
    output:none
    '''
    def do_GET(self, body=True):
        self.add_to_request_count()
        if check_for_too_much_requests(self.client_address[0]):
            db.insert_query('BannedIp',self.client_address[0])
        if check_for_banned_user(self.client_address[0]) and not brute_force_shut_down:
            self.send_error(403, "you are banned from this site" )
        else:
            sent = False
            global counter
            try:
                if self.requestline.find("?")!=-1:
                    potentialAttack=self.requestline[self.requestline.find("?")+1:self.requestline.find("HTTP")]
                    potentialAttack=list(urllib.parse.parse_qs(potentialAttack).values())
                    potentialAttack=flatten(potentialAttack)
                    potentialAttack=join_to_one_string(potentialAttack)
                else:
                    potentialAttack = self.requestline[self.requestline.find("/") + 1:self.requestline.find("HTTP")]
                    #checks if the attack might be in the html page request
                    if(len(potentialAttack)<2):
                        #checks if the attack might be trying to simulate a header
                        potentialAttack=(str(self.headers).split("\n"))[len(self.headers)-1]
                        potentialAttack=potentialAttack.split("=")
                        if (len(potentialAttack)<2 or (isBase64(potentialAttack[1]) == False and isBase64(potentialAttack[0])==False)):
                            potentialAttack = "=".join(potentialAttack)
                            potentialAttack = potentialAttack.split(":")
                            if (len(potentialAttack)<2 or (isBase64(potentialAttack[1]) == False and isBase64(potentialAttack[0])==False)):
                                potentialAttack = ":".join(potentialAttack)

                sent = self.riskDetector(potentialAttack)
                #checks if we haven't sent an answer that the packet contains an attack
                if(sent==False):
                    with open("GetSafe.txt","a") as f:
                        f.write(str(potentialAttack)+"\n")
                    url = 'http://{}{}'.format(hostname, self.path)
                    req_header = self.parse_headers()
                    resp = self.session.get(url, headers=merge_two_dicts(req_header, set_header()), verify=False)
                    sent = True
                    self.send_response(resp.status_code)
                    self.send_resp_headers(resp)
                    msg = resp.text
                    if body:
                        self.wfile.write(msg.encode(encoding='UTF-8',errors='strict'))
                    return
            except Exception as e:
                print(str(e))
            finally:
                if not sent:
                    self.send_error(404, 'error trying to proxy')

    '''
        This function is responsible to send an answer to all "POST" requests
        input:the "ProxyHTTPRequestHandler" object
        output:none
        '''
    def do_POST(self, body=True):
        sent = False
        try:
            url = 'http://{}{}'.format(hostname, self.path)
            content_len = int(self.headers.get('content-length'))
            post_body = self.rfile.read(content_len)
            potentialAttack = post_body.decode()
            potentialAttack=potentialAttack.split("=")
            if(len(potentialAttack)<2):
                potentialAttack="=".join(potentialAttack)
                try:
                    potentialAttack=json.loads(potentialAttack)
                    potentialAttack = potentialAttack.values()
                    potentialAttack=list(potentialAttack)
                    potentialAttack=[str(i) for i in potentialAttack]
                except:
                    pass
            else:
                potentialAttack=join_to_one_string(potentialAttack)
            sent=self.riskDetector(potentialAttack)
            if(sent==False):
                with open("postSafe.txt","a") as f:
                    f.write(str(potentialAttack)+"\n")
                req_header = self.parse_headers()
                resp = self.session.post(url, data=post_body, headers=merge_two_dicts(req_header, set_header()), verify=False)
                sent = True
                self.send_response(resp.status_code)
                self.send_resp_headers(resp)
                if body:
                    self.wfile.write(resp.content)
                return
        finally:
            if not sent:
                self.send_error(404, 'error trying to proxy')

    def do_POST(self, body=True):
        if check_for_banned_user(self.client_address[0]) and not brute_force_shut_down:
            self.send_error(403, "you are banned from this site" )
        else:
            sent = False
            try:
                url = 'http://{}{}'.format(hostname, self.path)
                content_len = int(self.headers.get('content-length'))
                post_body = self.rfile.read(content_len)
                potentialAttack = post_body.decode()
                potentialAttack=potentialAttack.split("=")
                if(isBase64(potentialAttack[0])==False):
                    potentialAttack="=".join(potentialAttack)
                    potentialAttack = potentialAttack.split(":")
                    if (isBase64(potentialAttack[0]) == False):
                        potentialAttack = ":".join(potentialAttack)
                sent=self.riskDetector(potentialAttack)
                if(sent==False):
                    with open("postSafe.txt","a") as f:
                        f.write(str(potentialAttack)+"\n")
                    req_header = self.parse_headers()
                    req_header["Host"]="127.0.0.1"
                    req_header["Content-Type"]="application/x-www-form-urlencoded"
                    req_header["Origin"]="http://127.0.0.1"
                    resp = self.session.post(url, data=post_body, headers=merge_two_dicts(req_header, set_header()), verify=False)
                    sent = True
                    self.send_response(resp.status_code)
                    self.send_resp_headers(resp)
                    if body:
                        self.wfile.write(resp.content)
                    return
            finally:
                if not sent:
                    self.send_error(404, 'error trying to proxy')

    def riskDetector(self,potentialAttack):
        riskScore = checker.checkRequestRisk(potentialAttack)
        if (riskScore >= riskLevel.MEDIUM_RISK):
            self.send_error(403, 'Attack was intercepted')
            return True
        print("No risk: "+str(potentialAttack)+ "Risk: "+str(riskScore))
        return False

    '''
    This function parses the headers of every packet
    input:the "ProxyHTTPRequestHandler" object
    output: the headers as a dictionary
    '''
    def parse_headers(self):
        req_header = {}
        for line in self.headers:
            line_parts = [o.strip() for o in line.split(':', 1)]
            if len(line_parts) == 2:
                req_header[line_parts[0]] = line_parts[1]
        req_header["Content-Type"] = "application/x-www-form-urlencoded"
        return req_header

    '''
    This function creates the response headers
    input:the "ProxyHTTPRequestHandler" object and the resp which is a parameter that decides which headers to send
    output:none
    '''

    def send_resp_headers(self, resp):
        respheaders = resp.headers
        for key in respheaders:
            if key not in ['Content-Encoding', 'Transfer-Encoding', 'content-encoding', 'transfer-encoding', 'content-length', 'Content-Length']:
                self.send_header(key, respheaders[key])
        self.send_header('Content-Length', len(resp.content))
        self.end_headers()


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):

    def __init__(self, server_address, RequestHandlerClass):
        threading.Thread.__init__(self)
        HTTPServer.__init__(self, server_address, RequestHandlerClass)

'''
This function checks if the string is encoded in base64
input: the user's request
output: a boolean statement whether the string was encoded in base64
'''
def isBase64(s):
    s=s.strip(" ")
    if(len(s)>2 and s[:-2]):
        s+="="
    if(re.search(RE_BASE64, s)):
        return True
    else:
        s += "="
        if (re.search(RE_BASE64, s)):
            return True
    return False

'''
This function flattens lists in lists into one list
input:a list object
output: a new list object without inner lists
'''
def flatten(l):
    return [item for sublist in l for item in sublist]



def main(argv=sys.argv[1:]):
    global db
    db = sqlite_database.DataBase()
    #db.insert_query('BannedIp','192.168.15.104')
    db.insert_query('PacketsPerMinute','"12121",3')
    ppm_thread = threading.Thread(target=db.delete_ppm_thread,daemon=True)
    ppm_thread.start()
    print('http server is starting on {} port {}...'.format(args.hostname, args.port))
    server_address = ("", 51234)
    httpd = ThreadedHTTPServer(server_address, ProxyHTTPRequestHandler)
    print('http server is running as reverse proxy')
    httpd.serve_forever()

if __name__ == '__main__':
    main()
