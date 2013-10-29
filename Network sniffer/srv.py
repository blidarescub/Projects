import hashlib
import string
from flask import Flask, request, render_template
import shlex, subprocess
import sys

app = Flask(__name__)
app.debug = True


@app.route('/')
def hello():
    print "Hello World!"
    return "Hello"

@app.route('/zone/<zone_id>/dns',methods=['POST'])
def rqdata(zone_id):
    print zone_id
    return zone_id

@app.route('/ips/<IP_id>/dns',methods=['POST'])
def rqdata(IP_id):
    print IP_id
    return IP_id


app.run(host='0.0.0.0')
