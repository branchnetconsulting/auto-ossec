~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Branch Network Consulting fork of Auto-Enroll for OSSEC
Extended by: Kevin Branch (Branch Network Consulting)
Version 1.5
Supported Systems: Linux, Windows
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This is a major rework of the original Auto-Enroll for OSSEC 1.3 (Binary Data Systems, David Kennedy)
It is not compatible with the Binary Data Systems Auto-Enroll for OSSEC.

Distinctives of this fork:
* auto_ossec registration requests are queued to resolve the problem of agent ID number collisions during parallel mass deployments
* auto_ossec.py works on Mac OS X systems (tested on El Capitan)
* auto_ossec.py allows agent systems without a static IP to specify a subnet that the agent will be required to connect from.  A subnet of 0.0.0.0/0 will remove all restriction on where an agent is allowed to connect from.
* 
* OSSEC restarts are done via /var/ossec/bin/ossec-control instead of via service command, because some OSSEC packages use a non-standard service name.  
* auto_ossec.py generates a new ossec.conf on the agent instead of appending to the existing ossec.conf file.
* OSSEC on the server is successfully restarted shortly after agent registrations.
* It assumes all agent settings other than <server-ip> and <config-profile> will be pulled down from the OSSEC server (agent.conf)
* It allowsaccepts an optional second parameter to specify a config-profile value.  It defaults to config-profile 'generic'.
* It stops and starts the OSSEC agent Linux service even when named "ossec-hids-agent" (like with the Wazuh rpm) rather than the stock service name "ossec"
* A script is provided for you to conveniently set your own unique cryptographic secret in both auto_ossec.py and auto_server.py.

Requirements:
* auto_server.py has only been tested on Linux systems, though it may work fine on a Mac OS X system running OSSEC server
* python-crypto must be installed
* Python 2.7 is required.  Dual Python 2.7 ad 3.5 support is planned.

Deployment and Usage:
* 
