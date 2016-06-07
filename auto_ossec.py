#!/usr/bin/python
#
# auto_ossec-bnc-1.3
#
# This is a fork by Kevin Branch (Branch Network Consulting) of BinaryDefense's ossec_client.py.
#
# Changes include:
# 	Overwrites ossec.conf instead of appends to it, and uses newlines
#	Takes optional second parameter to identify <config-profile> - defaults to 'generic'
#	Handles stop/start of Linux service even when named ossec-hids-agent(like Wazuh rpm)
#	Uses a different default secret key which must match the secret in auto_server.py
#	Validates reply from server instead of assuming a key was received
#
# This will connect to the ossec_auto.py daemon that will automatically issue a key in
# order to pair the OSSEC HIDS. 
#
# Also works with AlienVault.
#
# NOTE that you NEED to change the host = '' to the appropriate IP address of the OSSEC server and
# where the ossec_auto.py daemon is running.
#

import platform
import base64
import socket
import sys
import os
import subprocess
import time
import re

# try to import python-crypto
try:
	from Crypto.Cipher import AES

except ImportError:
	print ("[!] You need python-crypto in order for this module to work. If this is Ubuntu/Redhat - package name is python-crypto")
	sys.exit()

# check platform specific installs
installer = ""
if platform.system() == "Linux":
	installer = "Linux"

if platform.system() == "Windows":
	installer = "Windows"

if installer == "": 
	print ("[!] Unable to determine operating system. Only supports Linux and Windows. Exiting..")
	sys.exit()

#
# NEED TO DEFINE THIS AS THE OSSEC SERVER HOST THAT IS RUNNING SERVER.PY
#
try: 
	host = sys.argv[1]

except IndexError:
	print ("""
******************************************************
Binary Defense Systems OSSEC Auto Enrollment

In order for this to work, you need to point
auto_ossec.exe to the OSSEC server that is
listening. Note that default port is 9654
but this can be changed in the source.  

Usage: auto_ossec.exe <server_ip> <optional_config_profile_name>

*****************************************************
		""")
	sys.exit()

try: 
	oprofile = sys.argv[2]

except IndexError:
	oprofile = "generic"

def aescall(secret, data, format):

	# padding and block size
	PADDING = '{'
	BLOCK_SIZE = 32
	# one-liner to sufficiently pad the text to be encrypted
	pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING
	
	# random value here to randomize builds
	a = 50 * 5
	
	# one-liners to encrypt/encode and decrypt/decode a string
	EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))
	DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(PADDING)
	
	cipher = AES.new(secret)
	
	if format == "encrypt":
                aes = EncodeAES(cipher, data)
                return str(aes)

	if format == "decrypt":
                aes = DecodeAES(cipher, data)
                return str(aes)

# this will grab the hostname and ip address and return it
def grab_info():
        try:
                hostname = socket.gethostname()
                return hostname #+ " " + ipaddr
	
        except Exception:
                sys.exit()
try:
        # secret key - this must match the secret key in auto_server.py on the OSSEC server - would recommend changing it from the default published to git
        secret = "(3j+-sa!333hNA2u3h@*!~h~2&^lk<!B"
        # port for daemon
        port = 9654 
        # general length size of socket
        size = 1024 

        print ("[*] auto_ossec - OSSEC agent mass deployment tool")
        print ("[*] Branch Network Consulting fork, version 1.3")

        # loop through in case server isnt reachable
        while 1:
                try:
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
                        s.connect((host,port))
                        break

                except Exception: 
                        print ("[!] Unable to connect to destination server. Re-trying in 10 seconds.")
                        time.sleep(10)
                        pass 

        print ("[*] Connected to auto enrollment server at IP: " + host)

        # grab host info needed for ossec
        data = grab_info()

        # encrypt the data
        data = "BNCOSSEC" + data.rstrip()
        data = aescall(secret, data, "encrypt")
        print ("[*] Pulled hostname and IP, encrypted data, and now sending to server.")
        s.send(data) 




	while 1:
        	data = s.recv(size) 
	        data = aescall(secret, data, "decrypt")

	        if re.search("^[A-Za-z0-9]{100,}=?$",data):
	        	print ("[*] We received our new pairing key for OSSEC, closing server connection.")
	        	s.close()
			break

		elif data == "WAIT":
			print "The server is busy registering other agents.  Your registration request is in queue..."
		else:	
			print "Invalid or empty message received from server (wrong secret?).  Aborting..."
			print data
	        	s.close()
			sys.exit()





        # path variables for OSSEC
        if os.path.isdir("C:\\Program Files (x86)\\ossec-agent"): path = "C:\\Program Files (x86)\\ossec-agent"
        if os.path.isdir("C:\\Program Files\\ossec-agent"): path = "C:\\Program Files\\ossec-agent"
        if os.path.isdir("/var/ossec/"): path = "/var/ossec/"
        if path == "": sys.exit()
        print ("[*] Removing any old keys.")
        os.chdir(path)
	
        if installer == "Windows":
                if os.path.isfile("client.keys"): os.remove("client.keys")
                # import the key with the key presented from the server daemon
                filewrite = file(path + "\\client.keys", "w")

        if installer == "Linux":
                if os.path.isfile(path + "/etc/client.keys"): os.remove("etc/client.keys")
                filewrite = file(path + "/etc/client.keys", "w")


        data = base64.b64decode(data)
        filewrite.write(data)
        filewrite.close()
        #subprocess.Popen("echo y | manage_agents.exe -i %s" % data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True).wait()
        print ("[*] Successfully imported the new pairing key.")

        print ("[*] Stopping the OSSEC service, just in case its running.")
        # stop the service if it is
        if installer == "Windows":
                subprocess.Popen('net stop "OSSEC HIDS"', stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True).wait()

        if installer == "Linux":
                if os.path.isfile("/etc/init.d/ossec"):
                         subprocess.Popen("service ossec stop", stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True).wait()
                if os.path.isfile("/etc/init.d/ossec-hids-agent"):
                         subprocess.Popen("service ossec-hids-agent stop", stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True).wait()

        print ("[*] Creating a new ossec.conf to incorporate server host IP address and optional config-profile.")
        # make sure we modify the ossec.conf

        if installer == "Windows":
                filewrite = file(path + "\\ossec.conf", "w")
                filewrite.write(" <ossec_config>\n")
                filewrite.write("   <client>\n")
                filewrite.write("      <server-ip>%s</server-ip>\n" % (host))
                filewrite.write("      <config-profile>%s</config-profile>\n" % (oprofile))
                filewrite.write("   </client>\n")
                filewrite.write(" </ossec_config>\n")
                filewrite.close()

        if installer == "Linux":
                filewrite = file(path + "etc/ossec.conf", "w")
                filewrite.write(" <ossec_config>\n")
                filewrite.write("   <client>\n")
                filewrite.write("    <server-ip>%s</server-ip>\n" % (host))
                filewrite.write("      <config-profile>%s</config-profile>\n" % (oprofile))
                filewrite.write("   </client>\n")
                filewrite.write(" </ossec_config>\n")
                filewrite.close()

        # start the service
        if installer == "Windows":
                subprocess.Popen('net start "OSSEC HIDS"', stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True).wait() 

        if installer == "Linux":
                if os.path.isfile("/etc/init.d/ossec"):
                         subprocess.Popen("service ossec start", stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True).wait()
                if os.path.isfile("/etc/init.d/ossec-hids-agent"):
                         subprocess.Popen("service ossec-hids-agent start", stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True).wait()

        print ("[*] Finished. Started the OSSEC service. Auto Enrollment for OSSEC is now finished.")

except Exception as error:
        print ("[*] Something did not complete. Does this system have Internet access?")



	tb = sys.exc_info()[2]
	print tb.tb_lineno



        print (error)

