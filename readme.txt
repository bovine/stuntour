Automatically intercepts connections with destination port of 994.
Simply configure mIRC to directly connect to the IRC server on port 994.

--

You can launch mIRC with the DLL pre-loaded by running the STUNRUN.EXE
helper utility.

--

Alternatively, you can start MIRC32.EXE as you normally would, but be sure
to load the DLL manually in mIRC with the command (before you connect):
	/dll stuntour.dll load_stunnel

Note that you cannot put that line in the "Perform" script box since those
commands are run after mIRC successfully connects to the server.

If you use the manual loading technique and want to unload the library
hooks manually for some reason, use the command with:
	/dll -u stuntour.dll

