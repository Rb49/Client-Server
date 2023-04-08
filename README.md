# Client-Server Application

This application features an option for multiple clients to connect to a server over a LAN. This document will provide you with an overview of the features and functionality of this application, as well as instructions for how to interact with it and setting it up and running it on your local machine.

# Table of Contents

    - Features
    - Modes
    - Usage
    - Requirements
    - Connection process
		
# Features

My application packs several features that make it special.

## Reliable connection

    - Clients are connected via a reliable TCP/IP protocol connection.
    - Each client connects to its own connection socket which runs on a thread and is not affected by other non-admin connections.

## Security

    - Every interaction with the client as well as the server is encrypted using the AES-128 algorithm
    - Key transformation is made securely using the DH algorithm
    - Admin password is not stored as plain text, but as its hash. (SHA-256)
    - Clients that typed the correct admin password will not have access to other connections' symmetric keys.
		
## Timeout

A client can stay inactive for no more than 2 minutes. After 1 minute of inactivity, the server asks it to respond. If the timeout is exceeded, the client will be kicked, and its connection will be closed.

## Simple and intuitive GUI

The application features a simple and decorated GUI for the client, and a comfortable command-line display for the server side. Both displays record the time when each line was received.
The client can send messages to the server simply by pressing ‘Enter’ and can also clear all the messages it had received by pressing a centralized button.

## Variety of exception messages

    - There is a handful of different exception-handling messages that protects both the client and server from unwanted fatal exception.
    - At handling exceptions from typos, the clients receive the correct syntax.
		
# Modes

## Non admin services

    - /echo - The server will return the desired message
    - /time - The server will return the current server time
    - /close - The server will close the connection with the requesting client
    - /calculate - The server will return the answer of an arithmetic expression
    - /quadroot - The server will return the roots of a quadratic equation in the form of ax^2 + bx + c = 0
    - /help - The server will return a description of all the services
		
## Admin services

Please note the admin password is set to ```123```.

    - /shutdown - with the current admin password, a client requests a server shutdown that will shut down the server and close every active connection.
    - /log - with the current admin password, a client requests the admin server log that features documentation of every connection since the server was started. It does not contain encryption keys.
		
# Usage 

To run my Client-Server Application, follow the following steps:

	1. Open a terminal window and navigate to the application directory.
	2. Start the server by running the python file server.py.
	3. Open another terminal window and navigate to the application directory.
	4. Start a client by running the python file client.py.
	5. If the client could connect to the server successfully, the client GUI will appear. 
	6. A connection was created, and the server is listening!
	
# Requirements

The app requires Python and the following libraries:

	- socket
	- threading
	- random
	- tkinter
	- datatime
	- time
	- re
	- numpy
	- math
	- hashlib

# Connection process

This app doesn’t rely on hard-coded IP address and port. However, a connection will succeed only if both the server and client are on the same LAN.
The connection process happens as follow:

	1. The server opens a UDP socket that listens to broadcasts.
	2. The client opens its own UDP socket and broadcasts a request to every UDP port from 40000 to 65535 and waits for a response.
	3. When the server UDP socket receives the request, it opens a TCP socket, runs it and transmits its detail in broadcast back to the listening client.
	4. The client connects to the TCP socket.
	5. The client and the socket exchange their public keys, and both create a shared encryption key.
	6. They start communicating securely.
