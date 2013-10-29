import hashlib
import string
from flask import Flask, request, render_template
import shlex, subprocess
import sys

app = Flask(__name__)
app.debug = True

hash = hashlib.md5().hexdigest()
print "Current hash : " + hash



@app.route('/')
def hello():
    return "Hello World!"

@app.route('/puppet_kick/',methods=['POST', 'GET'])
def puppet_kick():
    searchword = request.args.get('key')
    
    if searchword == hash:
        command = shlex.split('puppet agent --test')
        task = subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE)

        (stdout, stderr) = task.communicate()
        print stdout
        return stdout
    else:
        return "Incorrect or missing API key :("




app.run(host='0.0.0.0')
