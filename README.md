~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Branch Network Consulting fork of Auto-Enroll for OSSEC
Extended by: Kevin Branch (Branch Network Consulting)
Version 1.5
Supported Systems: Linux, Windows
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This is a major rework of the original Auto-Enroll for OSSEC (Binary Data Systems)

* It generates a new ossec.conf on the agent instead of appending to the existing ossec.conf file.
* It assumes all agent settings other than <server-ip> and <config-profile> will be pulled down from the OSSEC server (agent.conf)
* It allowsaccepts an optional second parameter to specify a config-profile value.  It defaults to config-profile 'generic'.
* It stops and starts the OSSEC agent Linux service even when named "ossec-hids-agent" (like with the Wazuh rpm) rather than the stock service name "ossec"
* It queues incoming auto_ossec registration requests to resolve the problem of agent ID number collisions during parallel mass deployments
*   (https://github.com/BinaryDefense/auto-ossec/issues/3)

It is important to use both the forked ossec_client.py and ossec_server.py because client-server messaging has been adapted to support request queuing.


From original README:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Binary Defense Systems Auto-Enroll for OSSEC
Written by: David Kennedy - BDS
Version 1.3
Supported Systems: Linux, Windows
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The auto ossec enrollment will automatically provision OSSEC agents for both Linux and Windows. This is accomplished through a customized protocol
that interfaces with the ossec server and the automatic pairing of the server. 


Descriptions:

auto_server.py - this file contains the server to house the protocol - the port needed for this is 9654. The agents will communicate with the agents to this server script that is running. This server script should be placed in an automatic init script and through watchdog in order to ensure its always running. This script needs to be placed on the OSSEC server itself.

auto_ossec.exe and auto_ossec.py - auto_ossec.exe is to run on Windows, and auto_ossec.py to run on Linux. When running the tool you will need to issue auto_ossec.exe <ip_address_of_auto_server> - this will be the IP address of the server itself.

Deployment Instructions:

Install OSSEC server on a system. Ensure that auto_server.py is automatically started when reboot occurs, and watchdog in order to ensure its always running. Also ensure no iptables conflict with port 9654 - this port is needed for the two way communication.

Install OSSEC on a Linux or Windows system as an agent. Then run auto_ossec.exe or auto_ossec.py with the IP address of the SERVER that is running auto_server.py. This will automatically pair the instances of OSSEC.

NOTE THAT ALL OF THESE NEED TO BE PERFORMED WITH ROOT OR ADMINISTRATIVE LEVEL PERMISSIONS. THIS WILL FAIL IF IT IS NOT INSTALLED WITH ADMIN PRIVS.

Mass Deployment Instructions:

Create a deployment package that first installs the OSSEC binary or tar ball from (http://www.ossec.net/?page_id=19). Once the install completes, run the auto_ossec <server_ip> and you are finished. Services will automatically restart.

Ports Needed: 9654



What the server should look like when you run it in an interactive interface:

Client connected with  ('192.168.170.165', 50662)
[*] Provisioned new key for hostname: STRONGHOLD-WIN8 with IP of: 192.168.170.165
[*] Sending new key to 192.168.170.165: 8zlUouJ7yVOvt06Er8yx1zTchy5VQklfovu4SXW3GX7X8gH5tPIZ1104wvleQoZmJ9Hod++ByQtgNSLrQV7Z7rsRZLhCS9hFxPwRTZu6JC80EUXJ4yuTqFPHf9L2QuDjelP0yUvFFExf0xm7czlmDVH6/VKRdms1nL8+mwC9S81aZ0IOGpZuIMbIwiyeVxyBpctCk0Qd5CHoVZaKpAWTtA==
Pairing complete. Terminating connection to client.

