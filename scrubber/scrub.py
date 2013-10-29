#!/usr/bin/env python

import argparse
from dns import resolver
import os
import sys
import importlib
import redis
import smtplib
import socket
import re



curr_dir = os.getcwd()
config_DIR = 'CONFIG'



class RedisQueue(object):
    #Queue with Redis
    def __init__(self, name, namespace='queue', **redis_kwargs):
       self.__db= redis.Redis(**redis_kwargs)
       self.key = '%s:%s' %(namespace, name)

    def qsize(self):
        return self.__db.llen(self.key)

    def empty(self):
        return self.qsize() == 0

    def put(self, item):
        self.__db.lpush(self.key, item)

    def get(self, block=True, timeout=None):

        if block:
            item = self.__db.brpop(self.key, timeout=timeout)
        else:
            item = self.__db.bpop(self.key)

        if item:
            item = item[1]
        return item

    def get_nowait(self):
        return self.get(False)




class VerifyEmail(object):

    EMAIL_RE = re.compile('([\w\-\.+]+@\w[\w\-]+\.+[\w\-]+)')
    default_response = (550, 'Unknown')
    

    def resolve_mx(self,domain):
        ret = list()
        mxes = resolver.query(domain,'MX')

        for result in mxes:
            ips = resolver.query(result.exchange.to_text().rstrip('.'), 'A')

            for ip in ips:
                ret.append({
                    'name': result.exchange.to_text().rstrip('.'),
                    'preference': result.preference,
                    'ip': ip.address,
                })

        return ret


    
    def is_hostname_valid(self, hostname):
        """ if hostname is valid """
        try:
            socket.gethostbyname(hostname)
        except:
            return False
        return True

    def is_email_valid(self, email):
        """ if a given email maches the email pattern """
        return self.EMAIL_RE.search(email)

    def get_hostname_from_email(self, email):
        try:
            hostname = email.strip().split('@')[1]
            username = email.strip().split('@')[0]
        except:
            hostname = None
        return hostname, username

    #smtp server connection is returned or None
    def get_smtp_connection(self, hostname):
        resp = self.default_response
        connection_success = lambda x: x[0] == 220
        if self.is_hostname_valid(hostname):
            server = smtplib.SMTP()
            server.set_debuglevel(True)
            try:
                resp = server.connect(hostname)
            except:
                pass
            if connection_success(resp):
                return server
        return None
    
    def was_found(self, resp):
        return resp[0] == 250

    def not_found(self, resp):
        not_found_words = [
                "does not exist",
                "doesn't exist",
                "rejected", 
                "disabled",
                "discontinued",
                "unavailable",
                "unknown",
                "invalid",
                "doesn't handle",
        ]
        if resp[0] != 250 and any(a in resp[1].lower() for a in not_found_words):
            return True

    def could_not_verify_status(self, resp):
        return not (self.was_found(resp) or self.not_found(resp))
    
    def initial_connection(self,hostname):        
        #hostname = config.domain
        print hostname
        mx = self.resolve_mx(hostname)
        for m in mx:
            server = self.get_smtp_connection(m['name'])
            if server:
                return server

            
    def cmd_success(self,resp):
        return resp[0] == 250
                   
        

    def check(self, server, hostname, from_host, from_email):
        resp = self.default_response
        while True:
            
        
            if server:
                try:
                    resp = server.docmd('HELO %s' % from_host)
                except:
                    server = self.initial_connection(hostname)
                    if server:
                        resp = server.docmd('HELO %s' % from_host)                   
                        continue
                    
                
                if self.cmd_success(resp):
                    try:
                        resp = server.docmd('MAIL FROM: <%s>' % from_email)
                    except:
                        continue
                        
                    if self.cmd_success(resp):
                        try:
                            while True:
                                email = q.get()
                                if self.is_email_valid(email):
                                    if server:                                        
                                        resp = server.docmd('RCPT TO: <%s>' % email)
                                        if self.was_found(resp):
                                            print email
                                            c.put(email)
                                            email = None
                                            resp = None
                                        elif self.not_found(resp):
                                            b.put(email)
                                            email = None
                                            resp = None
                                    else:
                                        break
                        except:
                            continue
                        
                    
        #return resp

    

            
def verify_email_address(email,from_host,from_email):
    e = VerifyEmail()
    status = e.verify_email_smtp(email,from_host,from_email)
    if e.was_found(status):
        return True
    return status






if __name__ == '__main__':
    

    parser = argparse.ArgumentParser()
    parser.add_argument('-c','--config', help='Config file name',required=True)
    args = parser.parse_args()

    module = str(args.config)

    config_file_path = os.path.join(curr_dir,config_DIR)

    sys.path.append(config_file_path)
    
    
    config = importlib.import_module(module, package=None)
    

    q = RedisQueue('%s%s' %(config.queue,":unknown"))

    c = RedisQueue('%s%s' %(config.queue,":connected"))

    b = RedisQueue('%s%s' %(config.queue,":bounce"))
    

    e = VerifyEmail()

    srv = e.initial_connection(config.domain)

    e.check(srv, config.domain, config.sources[1], config.from_email)
    
    
        
        





