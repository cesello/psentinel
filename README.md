psentinel
=========
Is a flexible and small  daemon (~40kb)  that check and manage back-end nodes declared in a HAProxy
 and interact with it for automatic up/down
The idea behind psentinel is pretty simple: insert a daemon between haproxy and the back-end service
to decouple the service from the direct check.
Psentinel can execute a shell script/executable to check the monitored application and reply
to haproxy about the state.
It can be also manually disabled.

Installation
============

to install : make && make install 
to execute : psentinel -d 

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

Please read the documentation pdf for more..
