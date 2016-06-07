#!/usr/bin/python
#
# auto_server-bnc-1.3
#
# This is a fork by Kevin Branch (Branch Network Consulting) of BinaryDefense's auto_server.py script.  
# It has been updated to queue incoming registration requests so that parallel calls to /var/ossec/bin/manage_agents are not made.
# This resolves a known problem wherein many simultaneous registration requests cause agent ID collisions.
#
# Use this script in conjunction with the forked auto_ossec.py script.  Messaging between the client and server script has been adapted
# to support queuing of registration requests to resolve the agent id collision problem.
#
# This is the ossec auto enrollment server daemon. This should be put under supervisor to ensure health and stability.
#
#
# Works with Alienvault and Standlone OSSEC installs
#
# Will listen on port 9654 for an incoming challege
#
import SocketServer
from threading import Thread
import subprocess
import syss

# check python crypto library
try:
	from Crypto.Cipher import AES

except ImportError:
	print "[!] python-crypto not installed. Run 'apt-get install python-pycrypto pexpect' to fix."
	sys.exit()

import base64
import thread

# check pexpect library
try:
	import pexpect
except ImportError:
	print "[!] pexpect not installed. Run apt-get install pexpect to fix."
	sys.exit()

import time
import socket
import os

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
		secret = "(3j+-sa!333hNA2u3h@*!~h~2&^lk<!B"
        	print "Client connected with ", self.client_address
		try:	
			data = self.request.recv(1024)
		 	if data != "":
				try:
					data = aescall(secret, data, "decrypt")

					# if this section clears -we know that it is a legit request, has been decrypted and we're ready to rock
					if "BNCOSSEC" in data: 

						# Delete any entries in queue more than 1 hour old.  Those would be stale entries.
						os.popen("find /tmp/auto-ossec-queue/ -cmin +60 -exec rm -f {} \; ;")
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
							# print "This client is:   "+ctoken
							# print "First in line is: "+oldest
							# If our client is first in line then proceed to service them
							if ctoken == oldest:
								break
							# Otherwise wait a little bit, sending the "WAIT" message to the client every 5 seconds to ensure them they are in queue
							timer += 1
							if timer == 25:
								print "Sending WAIT message to "+ctoken
								self.request.send(aescall(secret, "WAIT", "encrypt"))
								timer = 0
							time.sleep(.2)

						# write a lock file to check later on with our threaded process to restart OSSEC if needed every 10 minutes - if lock file is present then it will trigger a restart of OSSEC server
						if not os.path.isfile("/tmp/aolock"): 
							filewrite = file("/tmp/aolock", "w")
							filewrite.write("lock")
							filewrite.close()

						# strip identifier
						data = data.replace("BNCOSSEC", "")
						hostname = data

						# pull the true IP, not the NATed one if they are using VMWare
						ipaddr = self.client_address[0]

						# here if the hostname was already used, we need to remove it and call it again
						data = parse_client(hostname, ipaddr)
						if data == 0: data = parse_client(hostname, ipaddr)




						# PAUSE FOR TESTING QUEUEING
						# time.sleep(5)




						# Remove client from queue
						os.popen("rm -f /tmp/auto-ossec-queue/"+ctoken)

						print "[*] Provisioned new key for hostname: %s with IP of: %s" % (hostname, ipaddr)
						data = aescall(secret, data, "encrypt")
						print "[*] Sending new key to %s: " % (ipaddr) + data
			                        self.request.send(data)

				except Exception, e:
					print e
					pass

		except Exception, e:
			print e
			pass

        	print "Pairing complete. Terminating connection to client."
       		self.request.close()

# this waits 5 minutes to check if new ossec agents have been deployed, if so it restarts the server
def ossec_monitor():
	time.sleep(300)
	if os.path.isfile("lock"):
		os.remove("lock")
		print "[*] New OSSEC agent added - triggering restart of service to add.."
		subprocess.Popen("service ossec restart", stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True).wait()

class ThreadedTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer): pass


# Upon auto-ossec server initialization, clear out the queue since anything there would be stale
os.popen("rm -f /tmp/auto-ossec-queue/*")

print ("[*] auto_ossec - OSSEC agent mass deployment server-side tool")
print ("[*] Branch Network Consulting fork, version 1.3")

print "[*] The auto enrollment OSSEC Server is now listening on 9654" 
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# set is so that when we cancel out we can reuse port
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
# bind to all interfaces on port 10900
t = ThreadedTCPServer(('',9654), service)
# start the server and listen forever
try:
	# start a threaded counter
	thread.start_new_thread(ossec_monitor,())

	t.serve_forever()

except KeyboardInterrupt:
	print "[*] Exiting the automatic enrollment OSSEC daemon"
