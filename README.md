psentinel
=========
Is a flexible and small  daemon (~40kb)  that checks and manages back-end nodes declared in a HAProxy
 and interacts with it for automatic up/down
The idea behind psentinel is pretty simple: runs between haproxy and a back-end application
to decouple it from the haproxy direct check.
Psentinel can execute a shell script/executable to check the back-end application and reply
to haproxy about the running state.
It can be also manually disabled, very usefull for manual or automatic deploy and continuous integration

Installation
============

From root user:

to compile/install : make && make install
 
to execute as daemon  : psentinel -d 

Probably is better to create and execute from an unprivileged user 
(please read the psentinel.pdf for more info)


Action
======

psentinel sends 200 OK to haprxy if monitored application is up and running
                503 Disabled if manually paused by user
                500 Error if the check script fails

Usage
=====

Psentinel executable can act as client or daemon.
as client (talking with daemon via AF_UNIX socket) is possible to know the status of monitored services

psentinel -c status

or disable one specific service

psentinel -c disable <serivice>

or pause all the pausable services

psentinel -c pause

Please read the psentinel.pdf for more..
