#!/usr/bin/python
#
# auto_ossec.py - BNC fork - version 1.5
#
# This is a fork by Kevin Branch (Branch Network Consulting) of BinaryDefense's auto_ossec.py.
#
# Changes include:
# 	Overwrites ossec.conf instead of appends to it, and uses newlines
#	Takes optional second parameter to identify <config-profile> - defaults to 'generic'
#	Handles stop/start of Linux service even when named ossec-hids-agent(like Wazuh rpm)
#	Uses a different default secret key which must match the secret in auto_server.py
#	Validates reply from server instead of assuming a key was received
#
# Use this script in conjunction with the forked auto_server.py.  Messaging between the client and server script has been adapted
# to support queuing of registration requests to avoid a known problem in the original auto-ossec 1.2 package.
#
# This will connect to the auto_server.py daemon that will automatically issue a key in
# order to pair the OSSEC HIDS. 
#
# This forked version should still work with AlienVault, but it has not been tested.
#

import platform
import base64
import socket
import glob
import sys
import os
import subprocess
import time
import re
import getopt 

# try to import python-crypto
try:
	from Crypto.Cipher import AES

except ImportError:
	print ("[!] You need python-crypto in order for this module to work. If this is Ubuntu/Redhat install package python-crypto.")
	sys.exit()

# check platform specific installs
installer = ""
if platform.system() == "Linux":
	installer = "Linux"

if platform.system() == "Windows":
	installer = "Windows"

if platform.system() == "Darwin":
	installer = "Mac"

# Check if OSSEC agent is installed.   If not, warn user and abort
if not os.path.isfile("C:\\Program Files (x86)\\ossec-agent\\ossec-agent.exe") and not os.path.isfile("C:\\Program Files\\ossec-agent\\ossec-agent.exe") and not os.path.isfile("/var/ossec/bin/ossec-agentd"):
	print ("[!] OSSEC agent is not installed on this system.  Install it before attempting to register it.")
	sys.exit()

if installer == "": 
	print ("[!] Unable to determine operating system. Only supports Linux, Windows, and Mac OS. Exiting..")
	sys.exit()

def showhelp():
        print ("""
***************************************************************************************************************************

Auto-Enroll for OSSEC, version 1.5 by Kevin Branch (Branch Network Consulting)
Forked from the original work of David Kennedy (Binary Defense Systems): Auto-Enroll for OSSEC, version 1.3

To enroll this OSSEC agent with an OSSEC server, run this program (auto_ossec.py or auto_ossec.exe)
specifying at a minimum the IP or name of the OSSEC server that is running auto_server.py.

auto_ossec.(py|exe) -s/--server OSSEC-SERVER [-h/--hostname HOSTNAME] [-n/--net NETWORK] [-p/--profile PROFILE(S)] [--help]

        OSSEC-SERVER - IP of OSSEC server running auto_server.py
        HOSTNAME - optional name to self register as, if you want to override the local host name
        NETWORK - network this agent will be limited to approaching the server from.  (0.0.0.0/0 means no restriction)
        PROFILE(S) - one or more OSSEC config profiles this agent is to be associated with for custom configs from server
                     (multiple profiles are allowed in csv format with no white space)

Usage example: auto_ossec.exe -s hids.xyz.com -n 192.168.150.0/24 -p finance,sensitive

***************************************************************************************************************************
                """)

try:
	options, remainder = getopt.getopt(sys.argv[1:], 's:h:n:p:', ['server=','hostname=','net=','profile=','help'])
	server = ""
	hostname = socket.gethostname()
	network = "none"
	profile = "none"

	for opt, arg in options:
	    if opt == '--help':
	        showhelp()
		sys.exit()
	    elif remainder:
	        print "\nInvalid extra parameter(s): ",remainder
	        showhelp()
		sys.exit()
	    elif opt in ('-s', '--server'):
		server = arg
	    elif opt in ('-h', '--hostname'):
	        hostname = arg
	    elif opt in ('-n', '--net'):
	        network = arg
	    elif opt in ('-p', '--profile'):
	        profile = arg

except Exception as error:
	print
        print (error)
	showhelp()
	sys.exit()

if server == "":
        print "\nYou must at least specify OSSEC server name or IP (-s/--server).\n"
        showhelp()
	sys.exit()

try: 
	socket.inet_aton(server)
except Exception as error:
        print "\nInvalid IP address for server parameter."
        showhelp()
        sys.exit()

pattern = re.compile("^(?:\d{1,3}\.){3}\d{1,3}(?:/\d\d?)?$")
if network != "none" and not pattern.match(network):
	print "\nThe specified network is not in valid IP CIDR format (like 192.168.200.0/24)"
        showhelp()
        sys.exit()

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

try:
        # Secret key - change this to something unique for your organization.  Keep the number of characters the same.
	# Make sure to also change the secret key in auto_server.py on the OSSEC server to the same value.
	# AES key must be 32 bytes long
	secret = "a3D48gDfgjdfg09853jklh2943123133"

        # port for daemon
        port = 9654 
        # general length size of socket
        size = 1024 

        print ("[*] auto_ossec - OSSEC agent mass deployment script")
        print ("[*] Branch Network Consulting fork, version 1.5")

	print '[*] OSSEC Server     :', server
	print '[*] Agent Hostname   :', hostname
	print '[*] Agent Network    :', network
	print '[*] Agent Profile(s) :', profile

        # loop through in case server isn't reachable
        while 1:
                try:
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
                        s.connect((server,port))
                        break

                except Exception: 
                        print ("[!] Unable to connect to destination server. Re-trying in 10 seconds.")
                        time.sleep(10)
                        pass 

        print ("[*] Connected to auto enrollment server at: " + server )

        # grab local host name to register agent under, unless this has been overridden with -h/--hostname
        if hostname == "":
        	try:
	                hostname = socket.gethostname()
		
	        except Exception:
	                sys.exit()

        # encrypt the data
        data = "BNCOSSEC," + hostname.rstrip() + "," + network.rstrip()
	unencrypted = data

        data = aescall(secret, data, "encrypt")
        print "[*] Sending registration request to server: ",unencrypted
        s.send(data) 

	# Handle incoming messages from the registration server until key is issued
	while 1:
        	data = s.recv(size) 
	        data = aescall(secret, data, "decrypt")

	        if re.search("^[A-Za-z0-9]{100,}=?=?$",data):
	        	print ("[*] We received our new pairing key for OSSEC, closing server connection.")
	        	s.close()
			break

		elif data == "WAIT":
			print "[*] The server is busy registering other agents.  Your registration request is in queue..."
		else:	
			print "[!] Invalid or empty message received from server (wrong secret?).  Aborting..."
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

        if installer in "Linux|Mac":
                if os.path.isfile(path + "/etc/client.keys"): os.remove("etc/client.keys")
                filewrite = file(path + "/etc/client.keys", "w")


        data = base64.b64decode(data)
        filewrite.write(data)
        filewrite.close()
        print ("[*] Successfully imported the new pairing key.")

        print ("[*] Stopping the OSSEC service, just in case its running.")
        # stop the service if it is running
        if installer == "Windows":
                subprocess.Popen('net stop "OSSEC HIDS"', stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True).wait()

        if installer in "Linux|Mac":
                subprocess.Popen("/var/ossec/bin/ossec-control stop", stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True).wait()

        print ("[*] Creating a new ossec.conf to incorporate server address and optional config-profile.")

        if installer == "Windows":
                filewrite = file(path + "\\ossec.conf", "w")
		ridslist = glob.glob(path + "\\rids\\*")

        if installer in "Linux|Mac":
                filewrite = file(path + "etc/ossec.conf", "w")
		ridslist = glob.glob("/var/ossec/etc/rids/*")

        filewrite.write(" <ossec_config>\n")
        filewrite.write("   <client>\n")
        filewrite.write("    <server-ip>%s</server-ip>\n" % (server))
        if profile != "none":
             	filewrite.write("      <config-profile>%s</config-profile>\n" % (profile))
        filewrite.write("   </client>\n")
        filewrite.write(" </ossec_config>\n")
        filewrite.close()

	# If any rids files exist from a previous registration, delete them to avoid out of sync rids problems
	for f in ridslist:
		os.remove(f)

        # start the service
        if installer == "Windows":
                subprocess.Popen('net start "OSSEC HIDS"', stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True).wait() 
        if installer in "Linux|Mac":
                subprocess.Popen("/var/ossec/bin/ossec-control start", stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True).wait()

        print ("[*] Finished. Started the OSSEC service. Auto Enrollment for OSSEC is now finished.")
	s.close()

except Exception as error:
        print ("[*] Something did not complete. Does this system have Internet access?")
	tb = sys.exc_info()[2]
	print "Line: ",tb.tb_lineno
        print (error)
