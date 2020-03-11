# Ps-Tools, an advanced process monitoring toolkit for offensive operations.
Having a good technical understanding of the systems we land on during an engagement is a key condition for deciding what is going to be the next step within an operation. Collecting and analysing data of running processes from compromised systems gives us a wealth of information and helps us to better understand how the IT landscape from a target organisation is setup. Moreover, periodically polling process data allows us to react on changes within the environment or provide triggers when an investigation is taking place.

To be able to collect detailed process data from compromised end-points we wrote a collection of process tools which brings the power of these advanced process utilities to C2 frameworks (such as Cobalt Strike).

More info about the tools and used techniques can be found on the following Blog: 
https://outflank.nl/blog/2020/03/11/red-team-tactics-advanced-process-monitoring-techniques-in-offensive-operations/

## The following functionality is included in the toolkit:

```
Psx: Shows a detailed list of all processes running on the system.
Psk: Shows detailed kernel information including loaded driver modules.
Psc: Shows a detailed list of all processes with Established TCP connections.
Psm: Show detailed module information from a specific process id (loaded modules, network connections e.g.).
Psh: Show detailed handle information from a specific process id (object handles, network connections e.g.).
Psw: Show Window titles from processes with active Windows.
```

## Usage:

```
Download the Outflank-Ps-Tools folder and load the Ps-Tools.cna script within the Cobalt Strike Script Manager.
Use the Beacon help command to display syntax information.
```

```
This project is written in C/C++
You can use Visual Studio to compile the reflective dll's from source.
```

## Credits
Author: Cornelis de Plaa (@Cneelis) / Outflank

Shout out to: Stan Hegt (@StanHacked) and all my other great colleagues at Outflank
