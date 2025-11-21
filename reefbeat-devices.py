#!/usr/bin/python3
import os
import sys
from   http.server import BaseHTTPRequestHandler, HTTPServer
import json
from types import SimpleNamespace
from threading import Thread,Event
import subprocess
import time
from signal import pthread_kill, SIGTSTP
import pathlib
import traceback
from jsonmerge import merge

class MyServer(HTTPServer):
    def __init__(self, handler,config):
        self.config = config
        self._db={}
        #Test if local IP exists
        must_create_ip=True
        for line in subprocess.Popen(
              ["ip", "addr", "show", "dev", "eth0"],
                stdout=subprocess.PIPE).communicate()[0].splitlines():
            if 'inet '+config.ip in str(line):
                must_create_ip=False
                break
        if must_create_ip:
            subprocess.Popen(["ip", "addr", "add", config.ip+"/24", "dev", "eth0"])
            print("Creating IP: %s "%config.ip)
            time.sleep(3)
        super().__init__((self.config.ip,self.config.port), handler)
        #fetch all_data and put them in cache
        for file_p in list(pathlib.Path().rglob("data")):
            file_s=str(file_p)
            path = file_s.replace('/data','').replace(self.config.base_url,'')
            self._db[path]={}
            with open(file_s) as f:
                if file_s.endswith('description.xml/data'):
                    data=f.read()
                else:
                    data = json.loads(json.dumps(json.load(f)).replace("__REEFBEAT_DEVICE_IP__",self.config.ip))
                self._db[path]['data']=data
                rights=[]
                if path not in self.config.access.no_GET:
                    rights+=['GET']
                methods=['POST','PUT']
                for method in methods:
                    if hasattr(self.config.access,method) and path in getattr(self.config.access,method):
                        rights+=[method]
                access={'rights':rights}
                self._db[path]['access']=access
        for action in self.config.post_actions:
            self._db[action.request]={}
            self._db[action.request]['access']={"rights":["POST"]}
            self._db[action.request]['action']=action.action


    def update_db(self, path,data):
        self._db[path]['data']=merge(self._db[path]['data'],data)
    
    def get_data(self,path):
        if path in self._db:
            if "data" in self._db[path]:
                return self._db[path]['data']
            else:
                return ""
        return None

    def is_allow(self,path,method):
        if method in self._db[path]['access']['rights']:
            return True
        else:
            print("[%s] %s on %s not allowed"%(self.config.name,method,path))
            return False
        
class HttpServer(BaseHTTPRequestHandler):

    def log(self,message):
        print("[%s] %s"%(self.server.config.name,message))
    
    def get_data(self,path):
        if path=='':
            path='/'
        return self.server.get_data(path)

    def log_message(self,format, *args):
        return 

    def log_reqst(self,method,r_data=""):
        self.log("%s %s %s"%(method,format(self.path),r_data))
    
    def do_GET (self):
        self.log_reqst("GET")
        data = self.get_data(self.path)
        if data and self.server.is_allow(self.path,"GET"):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(bytes(json.dumps(data),'utf8'))
        else:
            self.send_response(404)
            self.end_headers()

    def recv_with_param(self,method):
        content_length_str = self.headers.get('Content-Length')
        r_data=""
        if content_length_str:
            r_data=json.loads(self.rfile.read(int(content_length_str)))
        self.log_reqst(method,r_data)
        data=self.get_data(self.path)
        if data!=None and self.server.is_allow(self.path,method):
            self.send_response(200)
            self.end_headers()
            if r_data:
                post_action=self.server._db[self.path]['action']
                if post_action:
                    val=eval(post_action.action)
                    print(val)
                    self.server.update_db(post_action.target,val)
                else:
                    self.server.update_db(self.path,r_data)
            self.wfile.write(bytes('{"success":true}','utf8'))
        else:
            self.log("  ==>    %s %s:404"%(method,self.path))
            self.send_response(404)
            self.end_headers()
            
    def do_POST (self):
        if self.path=='/off':
            self.server.update_db('/mode',{'mode':'off'})
            self.send_response(200)
            self.end_headers()
            self.wfile.write(bytes('{"success":true}','utf8'))
            return
        self.recv_with_param("POST")
        
    def do_PUT (self):
        self.recv_with_param("PUT")

    def do_DELETE(self):
        self.log_reqst("DELETE")
        if self.path=='/off':
            self.server.update_db('/mode',{'mode':'auto'})
            self.send_response(200)
            self.end_headers()
            self.wfile.write(bytes('{"success":true}','utf8'))
            return

def ServerProcess(config):
    conf=json.loads(json.dumps(config), object_hook=lambda d: SimpleNamespace(**d))
    if conf.enabled:
        try:
            print("HTTP Server [%s] %s:%d running - Use Ctrl-C to terminate"%(conf.name,conf.ip,conf.port))
            httpd = MyServer(HttpServer,conf)
            while True:
                httpd.handle_request()
        except Exception as e:
            if os.geteuid() != 0:
                print("Acquiring 'sudo' privileges ...")
                os.system("sudo python{} {}".format(sys.version_info[0], ' "' + '" "'.join(sys.argv) + '"'))
            else:
                print("Unable to start server")
                print(traceback.format_exc())

if __name__ == "__main__":
    with open('config.json') as f:
        #confs = json.load(f, object_hook=lambda d: SimpleNamespace(**d))
        confs = json.load(f)

    threads=[]
    for conf in confs['devices']:
        thread = Thread(target = ServerProcess, args = [conf])
        threads+=[thread]
        thread.start()
        
    try:
        for thread in threads:
            thread.join()
    except KeyboardInterrupt:
        print("Bye")
    time.sleep(2)
    subprocess.run(["sudo","pkill","-9","-f","sudo ./reefbeat-devices.py"])
