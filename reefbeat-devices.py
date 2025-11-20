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

class MyServer(HTTPServer):
    def __init__(self, handler,config):
        self.config = config
        self.cache={}
        self.access={}
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
        
class HttpServer(BaseHTTPRequestHandler):
    def get_data(self,path):
        if path[0]=='/':
            path= path[1:]
        if path not in self.server.cache:
            try:
                with open(self.server.config.base_url+'/'+path+'/data') as f:
                    if path=='description.xml':
                        data=f.read()
                    else:
                        data = json.dumps(json.load(f))
                        data=data.replace("__REEFBEAT_DEVICE_IP__",self.server.config.ip)
                    self.server.cache[path]=data
                with open(self.server.config.base_url+'/'+path+'/access.json') as f:
                    self.server.access[path] = json.load(f)
            except Exception as e:
                print("Exception: %s"%e)
                return None
        return self.server.cache[path]
                
    def do_GET (self):
        print("You asked for : {}".format(self.path))
        data = self.get_data(self.path)
        if data:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(bytes(data,'utf8'))
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST (self):
        self.send_response(501)
        self.end_headers()

    def do_PUT (self):
        data=self.get_data(self.path)
        if data and "PUT" in self.server.access[self.path[1:]]['rights']: 
            self.send_response(200)
            self.end_headers()
            self.wfile.write(bytes('{"success":true}','utf8'))
        else:
            self.send_response(501)
            self.end_headers()

    def do_DELETE(self):
        self.send_response(501)
        self.end_headers()



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
                print(e)

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
