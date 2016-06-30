#!/usr/bin/python
#
# auto_server.py - BNC fork - version 1.5
#
# Use this script on your OSSEC server to accept registration requests from auto_ossec.py/exe on agent systems.
#
import SocketServer
from threading import Thread
import subprocess
import sys
import time
import base64
import time
import socket
import os

# check python crypto library
try:
	from Crypto.Cipher import AES

except ImportError:
	print ("[!] python-crypto not installed. Install python-crypto to fix.")
	sys.exit()

# check pexpect library
try:
	import pexpect
except ImportError:
	print ("[!] pexpect not installed. Install pexpect (Redhat/CentOS) or python-pexpect (Debian/Ubuntu) to fix.")
	sys.exit()

# Check if OSSEC server is installed.   If not, warn user and abort
if not os.path.isfile("/var/ossec/bin/ossec-monitord"):
	print ("[!] OSSEC server is not installed on this system.  Install it before using this script.")
	sys.exit()

class service(SocketServer.BaseRequestHandler):

	def handle(self):
		# parse OSSEC hids client certificate
		def parse_client(hostname, ipaddr):
			child = pexpect.spawn("/var/ossec/bin/manage_agents")
			child.expect("Choose your action")
			child.sendline("a")
			child.expect("for the new agent")
			child.sendline(hostname)
			i = child.expect(['IP Address of the new agent', 'already present'])
							
			# if we haven't already added the hostname
			if i == 0:
				child.sendline(ipaddr)
				child.expect("for the new agent")
				child.sendline("")
				for line in child: 
					# pull id
					if "[" in line: id = line.replace("[", "").replace("]", "").replace(":", "").rstrip()
					break
				child.expect("Confirm adding it?")
				child.sendline("y")
				child.sendline("")
				child.sendline("q")
				child.close()

				child = pexpect.spawn("/var/ossec/bin/manage_agents -e %s" % (id))
				for line in child:
					key = line.rstrip()

				return key
			
			# if we have a duplicate hostname
			else:
				child.close()
				child = pexpect.spawn("/var/ossec/bin/manage_agents -l")
				for line in child:
					line = line.rstrip()
					if hostname in line:
						id = line.split(",")[0].replace("ID: ", "").replace("   ", "").rstrip()
						break
				child.close()
				subprocess.Popen("/var/ossec/bin/manage_agents -r %s" % (id), stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True).wait()
				return 0

		
		# main AES encrypt and decrypt function with 32 block size padding
	        def aescall(secret, data, format):

		    # padding and block size
	            PADDING = '{'
	            BLOCK_SIZE = 32

	            # one-liner to sufficiently pad the text to be encrypted
	            pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING
	
	            # random value here to randomize builds
	            a = 50 * 5
	
	            # one-liners to encrypt/encode and decrypt/decode a string
	            # encrypt with AES, encode with base64
	            EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))
	            DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(PADDING)
	
	            cipher = AES.new(secret)
	
	            if format == "encrypt":
	                    aes = EncodeAES(cipher, data)
	                    return str(aes)
	
	            if format == "decrypt":
       	            	    aes = DecodeAES(cipher, data)
        	            return str(aes)

		# recommend changing this - if you do, change auto_ossec.py as well - - would recommend this is the default published to git
		# AES key must be 32 bytes long
		secret = "ABABABABABABABABABABABABABABABAB"

        	print ("[*] "+time.strftime("%Y-%m-%d %H:%M:%S")+" Client connected with ", self.client_address)
		try:	
			data = self.request.recv(1024)
		 	if data != "":
				try:
					data = aescall(secret, data, "decrypt")

					# if this section clears -we know that it is a legit request, has been decrypted and we're ready to rock
					if "BNCOSSEC," in data: 

						# Delete any entries in queue more than 1 hour old.  Those would be stale entries.
						os.popen("find /tmp/auto-ossec-queue/ -type f -cmin +60 -exec rm -f {} \; ;")
						# Create client token for a name in the queue.  Just use IP address for now.  
						ctoken = self.client_address[0]
						# Put client in queue
						os.popen("touch /tmp/auto-ossec-queue/"+ctoken)
						# Must be in the queue directory to find the oldest file
						os.chdir("/tmp/auto-ossec-queue" )
						
						timer = 0
						while 1:
							# find oldest client in queue (first in line)
							oldest=min(os.listdir('/tmp/auto-ossec-queue'), key = os.path.getctime)
														# If our client is first in line then proceed to service them
							if ctoken == oldest:
								break
							# Otherwise wait a little bit, sending the "WAIT" message to the client every 5 seconds to ensure them they are in queue
							timer += 1
							if timer == 25:
								print ("[*] "+time.strftime("%Y-%m-%d %H:%M:%S")+" Sending WAIT message to "+ctoken)
								self.request.send(aescall(secret, "WAIT", "encrypt"))
								timer = 0
							time.sleep(.2)

						# write a lock file to check later on with our threaded process to restart OSSEC if needed every 10 minutes - if lock file is present then it will trigger a restart of OSSEC server
						if not os.path.isfile("/tmp/aolock"): 
							filewrite = file("/tmp/aolock", "w")
							filewrite.write("lock")
							filewrite.close()

						discard,hostname,ipaddr = data.split(",")

						# pull the true IP, not the NATed one if they are using VMWare
						if ipaddr == "none":
							ipaddr = self.client_address[0]

						# here if the hostname was already used, we need to remove it and call it again
						data = parse_client(hostname, ipaddr)
						if data == 0: data = parse_client(hostname, ipaddr)

						# Remove client from queue
						os.popen("rm -f /tmp/auto-ossec-queue/"+ctoken)

						print ("[*] "+time.strftime("%Y-%m-%d %H:%M:%S")+" Sending newly provisioned key: " + data.decode('base64'))
						data = aescall(secret, data, "encrypt")
			                        self.request.send(data)

					else:
						print  ("[*] "+time.strftime("%Y-%m-%d %H:%M:%S")+" Client at "+str(self.client_address)+" submitted an invalid message.  Perhaps it used the wrong secret.")

				except Exception as e:
					print (e)
					pass

		except Exception as e:
			print (e)
			pass

        	print ("[*] "+time.strftime("%Y-%m-%d %H:%M:%S")+" Terminating connection to client: "+str(self.client_address))
       		self.request.close()


class ThreadedTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer): 
	# Ctrl-C will cleanly kill all spawned threads
	daemon_threads = True
	# much faster rebinding
	allow_reuse_address = True


# Upon auto-ossec server initialization, create queue directory or clear it out if present since anything there would be stale
if not os.path.exists("/tmp/auto-ossec-queue"):
	os.makedirs("/tmp/auto-ossec-queue")
else:
	os.popen("rm -f /tmp/auto-ossec-queue/*")

print ("\n[*] auto_ossec - OSSEC agent mass deployment server-side tool")
print ("[*] Branch Network Consulting fork, version 1.5")

print ("[*] "+time.strftime("%Y-%m-%d %H:%M:%S")+" The auto enrollment OSSEC Server is now listening on 9654")
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# set is so that when we cancel out we can reuse port
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

import struct
l_onoff = 1                                                                                                                                                           
l_linger = 0                                                                                                                                                          
s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', l_onoff, l_linger))

# bind to all interfaces on port 9654
t = ThreadedTCPServer(('',9654), service)
# start the server and listen forever
try:
	t.serve_forever()

except KeyboardInterrupt:
	print ("[*] "+time.strftime("%Y-%m-%d %H:%M:%S")+" Exiting the automatic enrollment OSSEC daemon")
	t.shutdown()
	t.socket.close()
	sys.exit(0)
