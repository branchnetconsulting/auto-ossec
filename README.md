~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Branch Network Consulting fork of Auto-Enroll for OSSEC
Extended by: Kevin Branch (Branch Network Consulting)
Version 1.5
Supported Systems: Linux, Windows, Mac OS X
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This is a major rework of the original Auto-Enroll for OSSEC 1.3 (Binary Data Systems, David Kennedy)

It is not compatible with the Binary Data Systems Auto-Enroll for OSSEC.

Distinctives of this fork:
* auto_ossec registration requests are queued to resolve the problem of agent ID number collisions during parallel mass deployments
* auto_ossec.py works on Mac OS X systems (tested on El Capitan)
* auto_ossec.py allows agent systems without a static IP to specify a subnet that the agent will be required to connect from.  A subnet of 0.0.0.0/0 will remove all restriction on where an agent is allowed to connect from.
* auto_ossec.py allows the host name used for registration to be overridden.  (good with systems that have non-distintive names)
* auto_ossec.py allows one or more OSSEC config profiles to be specified for inclusion in the ossec.conf file. (http://ossec-docs.readthedocs.io/en/latest/syntax/head_ossec_config.client.html)
* auto_ossec.py generates a new ossec.conf on the agent instead of appending to the existing ossec.conf file. This way, rerunning auto_ossec.py doesn't keep tacking more lines on the end of ossec.conf, which can cause confusion about which server to connect to.
* OSSEC restarts are done via /var/ossec/bin/ossec-control instead of via service command, because some OSSEC packages use a non-standard service name (i.e. Security Onion's ossec-hids-server package).  
* OSSEC on the server is successfully restarted shortly after agent registrations.  This was broken in the BDS 1.3 version of auto-ossec.
* A script is provided for you to conveniently set your own unique cryptographic secret in both auto_ossec.py and auto_server.py.
* More detailed logging and greater system and data validation have been added.

Requirements:
* auto_server.py has only been tested on Linux systems, though it may work fine on a Mac OS X system running OSSEC server
* python-crypto must be installed
* Python 2.7 is required.  

To Do:
* Put deployment and usage guides in the wiki: https://github.com/branchnetconsulting/auto-ossec/wiki
* Add dual Python 2.7 / 3.5 support.
* Make auto_server.py log to syslog.


