---
title: Offensive API Hooking
author: Ilan Kalendarov
date: 2021-02-10 14:10:00 +0800
categories: [Red Team]
tags: [persistence, av evasion]

---

## Introduction

Hooking is not a new concept as we know by now, many AV/EDR vendors use this technique to monitor suspicious API calls. In this blog post we'll explorer API hooking but in the offensive point of view. We'll use API Monitor to investigate which API calls used by each program  then, using Frida and python to build our final hooking script. This post is inspired by the Red Teaming Experiments 

[blog]: https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/instrumenting-windows-apis-with-frida



## API Monitor

Api Monitor is a great tool for .. you guest it, monitoring api calls. You can find it 

[here]: http://www.rohitab.com/downloads

Firing up Api Monitor this will be the main screen:

![](C:\Users\ilanka\Documents\GitHub\IlanKalendarov.github.io\Images\ApiMonitorHomeScreen.png)

As you can see I've chosen all of the library's options for seeing all of the API possibilities. Let's start by monitoring a new process, I'll choose runas.exe first.

According to microsoft's docs:

> It allows a user to run specific tools and programs with different permissions than the user's current logon provides.

Looks good to me as a start. So opening runas and trying to login as a different user gives us the above API call:

![](C:\Users\ilanka\Documents\GitHub\IlanKalendarov.github.io\Images\RunasAPICall.png)

Great so we know that `CreateProcessWithLogonW` is contains our secret password. Looking at the 

[msdn docs]: https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithlogonw

 we could see that the first and third arguments will store the username and password. Now that we have that information lets build our script!.

# Frida




