#!/usr/bin/env python2.7

import os
import datetime
import argparse
import whois
import sys
import Queue
import threading
import time
import socket
import operator
import itertools
from collections import defaultdict
from scapy.all import *
import requests
import json
from daemon import runner
import ConfigParser
import recipe_whois

config = ConfigParser.ConfigParser()

config.read("config.ini")

curr_dir = os.getcwd()

if config:

    httpserver = config.get("MAIN", "http_server")
    
    destination = config.get("MAIN", "folder")
    whois_destination = config.get("MAIN","whois_folder")
    
    if not os.path.exists(os.path.join(curr_dir, destination)):
                          os.mkdir(os.path.join(curr_dir, destination))

    
    if not os.path.exists(os.path.join(destination,whois_destination)):
                          os.mkdir(os.path.join(curr_dir, destination, whois_destination))


queue = Queue.Queue()

IPQueue = Queue.Queue()

           
log_files = {}
whois_logs = {}

list_by_zones = []
list_by_IP = []


class Packet:
    def __init__(self, time, ipsrc, port, sname, szone, qtype):
        self.time = str(time)
        self.ipsrc = str(ipsrc)
        self.sname = str(sname)
        self.szone = str(szone)
        self.qtype = str(qtype)
        self.port = str(port)
        
    def display_packet(self):
        return self.time + "    " + self.ipsrc + "    " + self.port + "    " + self.sname + "    " + self.szone + "    " + self.qtype

class Thread_Whois(threading.Thread):
    def __init__(self, queue):
        threading.Thread.__init__(self)
        self.queue = queue
          
    def run(self):
        while True:
            
            #grabs IP from queue
            target = self.queue.get()
            
            #WHOIS execution
            try:
                response = whois_query(target)
            except:
                response = "%s No data" %target

            try:
                x = socket.gethostbyaddr(target)
            except socket.herror:
                x[0] = 'No results'

            host_addr = x[0]
            
            
            out = open(os.path.join(curr_dir, destination, whois_destination, target + '.log'), 'a')
            out.write('%s\n' % response)
            out.flush()
            os.fsync(out.fileno())

            IPQueue.put([target,dict(ip = target, whois = response, host = host_addr)])
            
            
            #signals to queue job is done
            self.queue.task_done()
            time.sleep(5)


class Thread_aggregate_zone(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
          
    def run(self):
        list_zones = list()
         
        while True:
            zlist = defaultdict(list)
            
            while len(list_by_zones) > 0:
                #grabs list from zones list
                list_zones.append(list_by_zones.pop())
            
            
            
            # execution
            for a, b in list_zones:
                zlist[a].append(b)
            if len(zlist) > 0:
                for item in zlist.items():
                    zn = item[0]
                    payload = item[1]
                    
                    url = "http://" + httpserver + ":5000/zone/" + zn + "/dns/"
                    r = requests.post(url, data=json.dumps(payload))
                
                list_zones[:] = []
                
            time.sleep(10)


class Thread_aggregate_IP(threading.Thread):
    def __init__(self,queue):
        threading.Thread.__init__(self)
        self.queue = queue
          
    def run(self):
        list_IPs = list()
         
        while True:
            IPlist = defaultdict(list)
            
            while not self.queue.empty():
                #grabs list from IPQueue
                list_IPs.append(self.queue.get())
            
            
            
            # execution
            for a, b in list_IPs:
                IPlist[a].append(b)
            if len(IPlist) > 0:
                for item in IPlist.items():
                    IP = item[0]
                    payload = item[1]
                    
                    url = "http://" + httpserver + ":5000/ips/" + IP + "/dns/"
                    r = requests.post(url, data=json.dumps(payload))
                
                list_IPs[:] = []
                
            #self.queue.task_done()                
            time.sleep(10)



def scanner(pkt):
    if pkt.haslayer(DNSQR):
        q = pkt.getlayer(DNSQR)
        tokens = ('.' + q.qname.rstrip('.')).rsplit('.', 2)
        name , zone = tokens[0].lstrip('.'), '.'.join(tokens[-2:])
        timestamp = datetime.datetime.utcnow().replace(microsecond=0)
        sname=name or '@'
        szone=zone
        qtype=q.sprintf('%qtype%')
        ipsrc=pkt.sprintf('%IP.src%')
        port=pkt.sprintf('%UDP.dport%')

        a = Packet(timestamp,ipsrc,port,sname,szone,qtype)

        log(a)
        whois_log(a)
        
        list_by_zones.append([a.szone,dict(timestamp=a.time, ip=a.ipsrc, query=a.qtype)])

        
        
def whois_query(address):
    who = recipe_whois.NICClient()
    options = {}
    try:
        result = who.whois_lookup(options,address,0x01)
        return result
    except:
        return "ERROR"


def whois_log(packet):
    if packet.ipsrc not in whois_logs:
        whois_logs[packet.ipsrc] = open(os.path.join(curr_dir, destination, whois_destination, packet.ipsrc + '.log'), 'a')
        queue.put(packet.ipsrc)
        

def log(packet):
    if packet.szone not in log_files:
        log_files[packet.szone] = open(os.path.join(curr_dir, destination, packet.szone + '.log'), 'a')
    log_files[packet.szone].write('%s\n' % packet.display_packet())
    log_files[packet.szone].flush()
    os.fsync(log_files[packet.szone].fileno())
    
    print packet.display_packet()
    
class App():
    def __init__(self):
        self.stdin_path = '/dev/null'
        self.stdout_path = '/dev/tty'
        self.stderr_path = '/dev/tty'
        self.pidfile_path =  '/tmp/foo.pid'
        self.pidfile_timeout = 5
    def run(self):
        while True:
            
            if __name__ == '__main__':

                

                t = Thread_Whois(queue)
                t.setDaemon(True)
                t.start()
                
                m = Thread_aggregate_zone()
                m.setDaemon(True)
                m.start()

                n = Thread_aggregate_IP(IPQueue)
                n.setDaemon(True)
                n.start()
                

                try:
                    sniff(filter='udp src port 53', prn=scanner, store=0)
                except KeyboardInterrupt:
                    exit(0)
                finally:
                    for logfile in log_files:
                        log_files[logfile].close()
                        print "Closed %s" % log_files[logfile].name
                    for whois_log in whois_logs:
                        whois_logs[whois_log].close()
                        print "Closed %s" % whois_logs[whois_log].name
   

                         
                queue.join()
                IPQueue.join()
          
app = App()
daemon_runner = runner.DaemonRunner(app)
daemon_runner.do_action()
