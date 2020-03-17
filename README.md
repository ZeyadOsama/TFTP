# Trivial File Transfer Protocol (TFTP)

<p>
  <img src="https://img.shields.io/pypi/status/Django.svg"/>
</p>

<p>
Although it may sound similar, TFTP works differently than FTP (File Transfer Protocol) and HTTP (HyperText Transfer Protocol). Although TFTP is also based in FTP technology, TFTP is an entirely different protocol. Among the differences is that TFTP’s transport protocol uses UDP which is not secure while FTP uses Transmission Control Protocol (TCP) to secure information.
</p>
<p>
TFTP was primarily designed to read or write files by using a remote server. However, TFTP is a multi-purpose protocol that can be leveraged for an array of different tasks.
</p>

## Features
* Uploading and downloading files
* ``` octet ``` mode is used
* Follows <a href="https://tools.ietf.org/html/rfc1350">RFC</a>

## Setting Up
### 1. Setting Server
As this is a client implementation for TFTP you'll need to set your laptop/PC as a server

#### macOS
It has a built-in TFTP server. It is not loaded by default but enabling it is pretty easy. The easiest way to accomplish that is to simply type the following command in a Terminal window:
```
sudo launchctl load -F /System/Library/LaunchDaemons/tftp.plist
```
You’ll be prompted to provide your macOS password to proceed. Once installed, you can use the netstat command to confirm it is running:
```
netstat -n | grep *.69
```
This will then show up.
```
udp4 0 .69 .*
udp6 0 .69 .*
```
This tells you that the TFTP server is listening on port 69, waiting for connections and that it will accept both IP V4 and IPI V6 connections.

If you need to shut down the TFTP server, simply use the unload command:
```
sudo launchctl unload -F /System/Library/LaunchDaemons/tftp.plist
```

#### Linux

Linux is a very popular operating system and it’s not rare to see network administrators using it. Most Linux distributions come with at least one TFTP server, although it is rarely enabled–or even installed–by default. It’s still there, though as part of a package which is often called TFTPd, with the “d” standing for Daemon, the Unix name for an application that runs in the background. It is similar in functionality to a Windows service.

#### Windows
<a href="https://sourceforge.net/projects/tftputil/">Windows TFTP Utility</a>. Despite its name, this tool not from Microsoft. the Windows TFTP Utility is actually a barebones TFTP server for Windows.

### 2. Wireshark
Use this <a href="https://www.wireshark.org">link</a> to download Wireshark. This tool will be helping you test your uploaded and downloaded packets.

## Usage
#### Upload
```
python3 <script-name> <ip-addres> push <file-name-on-server>
```
#### Download
```
python3 <script-name> <ip-addres> pull <file-name-on-server>
```
