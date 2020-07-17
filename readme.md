StunTour: SSL Enabler for mIRC
==============================


Background
----------
Being able to connect securely to SSL-enabled IRC chat servers is something 
that remains difficult for most Win32 IRC applications. Very few IRC clients 
natively support connecting to servers with SSL, and the few that do are 
generally of very poor quality.

If you want to securely use a client such as the popular Win32 <a href="http://www.mirc.com">
mIRC</a> client, then you must generally resort to running a separate 
tunneling application (such as <a href="http://www.stunnel.org/">stunnel</a>) 
and then make mIRC to connect to a port bound to a localhost listening socket. 
This has the added overhead of requiring another application to be running at 
all times, and makes it difficult to change what server you connect to since 
you must manipulate the destination of the tunnel application. Also, running an 
external program is inconvenient and prone to problems.</p>

What is it?
-----------
After growing tired of fighting with stunnel, I decided to write a mIRC plugin 
DLL that would natively allow it to connect to SSL-enabled IRC servers. 
StunTour is a utility that automatically intercepts connections with 
destination port of 994. This allows you to connect to IRC servers using a 
secure SSL connection (provided that the server supports connecting over SSL on 
port 994).

There are currently very few IRC networks that support SSL connections. However, 
one IRC network that this program has been tested with is <a href="http://www.cuckoo.com/irc/">
CuckooNet IRC</a> (irc.cuckoo.com or irc.distributed.net), which is the IRC 
network run primarily for the users of <a href="http://www.distributed.net">distributed.net</a>.</p>

Due to the hooking technique that is being used, this program is only compatible 
with Windows 2000 and Windows XP machines.&nbsp; It will not work on Windows 
95, Windows 98, or Windows Me.</P>


How do I load it?
-----------------
* You can run the STUNRUN.EXE helper utility instead of MIRC.EXE when you want to 
start mIRC. This is the easiest and the recommended&nbsp;method.&nbsp; This 
causes mIRC to be automatically launched with the DLL pre-loaded. You should 
ensure that mIRC is not already running when you do this.

```
	STUNRUN.EXE
```
* You can start MIRC.EXE as you normally would, but load the DLL manually in mIRC 
with the command (before you connect):
```
/dll stuntour.dll load_stunnel
```
* You can start MIRC.EXE as you normally would, but have the DLL loaded 
automatically with scripting. Simply add this line to your "Remote" script tab:
```
on *:start: { /dll stuntour.dll load_stunnel }
```
Note that you cannot put a the dll load lines in the "Perform" script box since 
those commands are run <i>after</i> mIRC successfully connects to the server.


If you use the manual loading techniques (methods 2 or 3) and want to unload 
the library hooks manually for some reason without having to exit mIRC, use the 
following command:
```
	/dll -u stuntour.dll
```

Okay it's loaded, how do I use it?
----------------------------------
StunTour is a automatically intercepts connections with destination port of 
994. Simply configure mIRC to directly connect to the IRC server on port 994 
and that connection will be automatically wrapped in an SSL encrypted 
tunnel.  Actually, by default StunTour currently allows any of the 
following ports to be used:
		<UL>
			<LI>
			994 (standard RFC allocated port for IRCS)
			<LI>
			7000, 7001, 7002, 7003 (blabber.net and others)
			<LI>
			6657&nbsp;(sirc.hu)
			<LI>
			6697 (axenet)
			<LI>
			6699 (P2PChat)
			<LI>
			7032 (irdsi)
			<LI>
			6670 (NexusIRC)
			<LI>
			9998, 9999 (suidnet, chatsages)
			<LI>
			6999 (Biteme-irc)
			<LI>
			6000 (wondernet)
			<LI>
			9000 (chatchannel)
			<LI>
				25401</LI></UL>

You can also customize the list of ports the StunTour will intercept, in case 
you need to connect to a server using a different port (see below). 
Contact me if your IRC network uses a port that is not listed and I'll 
add it to a future version so that it will be intercepted for new StunTour 
users by default, as long as I don't think that the port number overlaps with a 
commonly used plaintext port number.  However I greatly recommend that you 
to try to contact the operators of your IRC network and encourage them to use 
the RFC allocated standard port of 994 first.
				
If you attempt to make IRC connections to a server on any other port, then a 
normal unencrypted connection will be made.&nbsp; Since mIRC 6.x allows 
multiple simultaneous connections to different servers to be made, this allows 
you to be connected to both SSL and non-SSL servers using the same instance of 
mIRC.&nbsp; Similarly, you can be connected to multiple SSL servers as well.</P>

How does it work?
-----------------
I'm using a the <a href="http://www.openssl.org/">OpenSSL</a> library for the 
implementation of the encryption layer, and the <a href="http://research.microsoft.com/sn/detours/">
Microsoft Detours</a> library to perform API interception/hooking on 
several of the standard Winsock functions. From mIRC's perspective, it is still 
opening an unencrypted connection to the server, but my code is doing the 
necessary work to ensure that the actual connection is actually SSL encrypted. 
I do this by using the Microsoft Detours library to intercept the Winsock <nobr>connect()</nobr>,
<nobr>send()</nobr>, <nobr>recv()</nobr>, etc functions and making them utilize 
the OpenSSL equivalents when a connection is made to a remote server on port 
994.

This product includes cryptographic software written by Eric Young (<A href="mailto:eay@cryptsoft.com">eay@cryptsoft.com</A>)</P>

How can I connect to an IRC server that uses SSL on another port?
-----------------------------------------------------------------
There are two ways to tell StunTour to perform automaticic SSL interception on 
additional port numbers:
				
1. Use the dynamic-library command to add interception for only this instance of 
  mIRC (will not be remembered for future launches of mIRC/StunTour):
* Inside mIRC, issue the command (where <i>xxx</i> is the port number you want to 
perform interception on):
`/dll stuntour.dll hook_ports <i>xxx</i>`
* Any future server connections made to that destination port number will now utilize SSL.
* If you restart mIRC/StunTour, ports that were added to the interception list 
using the above command will no longer be hooked.

2. Alter your registry to allow StunTour to always perform interceptions on 
  certain port numbers.
* You should use REGEDIT (Registry Editor) to navigate to this location:
```
HKEY_CURRENT_USER\Software\Bovine Networking Technologies, Inc.\StunTour
```
* Edit the MULTI-SZ value named `Ports` and add any additional port numbers there.
* (Note that the default ports that StunTour intercepts cannot be removed from the list.)
* You must restart mIRC/StunTour if they are already running for the changes to
  the Registry to take effect.


How can I always accept SSL certificate confirmation prompts?
-------------------------------------------------------------
Each time you connect to an IRC server over SSL, StunTour displays a 
confirmation dialog that includes details about the server's certificate, the 
issuer of the certificate, the address of the server, and other pre-validation 
information.&nbsp;If you ensure that the "remember this decision" checkbox is 
checked before clicking the "Yes" button, StunTour will no longer prompt you 
for connections made to a server utilizing that certificate.</p>

Alternatively, you can disable confirmation dialogs for all certificates by 
using REGEDIT (Registry Editor) to navigate to this location:
```
HKEY_CURRENT_USER\Software\Bovine Networking Technologies, Inc.\StunTour
```
then change the DWORD value `AlwaysAllowAnyCert` to be non-zero. Understand that
doing this is insecure since it can allow "man-in-the-middle" attacks to intercept
the connection  establishment and use an alternate certificate without you noticing.\

						
Why is it named "StunTour"?
---------------------------
The name is simply a shortened contraction of "SSL tunnel detour". The word 
"detour" is simply the name of the API hooking library that I'm using to 
perform some of the critical network interception calls.</p>


Contact: Jeff Lawson <jlawson@bovine.net>
