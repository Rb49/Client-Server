# modules
import socket
import threading
import random
import tkinter as tk
from datetime import datetime
import time
# utils
import cryptography


# this is client side


def create_gui() -> tuple:
	"""
	creates the gui elements, defines their attributes, and returns them
	:return: window, title_label, listbox, input_box, clear_button
	"""
	# Create the main window
	window = tk.Tk()

	window.minsize(500, 400)

	# get the screen dimension
	window_width = 1280
	window_height = 720
	window.geometry(
		f'{window_width}x{window_height}+{int(window.winfo_screenwidth() / 2 - window_width / 2)}+{int(window.winfo_screenheight() / 2 - window_height / 2)}')

	# add title
	window.title("Client side")
	window.configure(bg="#2C205B")

	# Create a label for title
	title_label = tk.Label(
		window,
		text="Client side",
		fg="#A3FF75",
		font=('Calibri', '26', 'bold'),
		bg="#33217C"
	)
	title_label.grid(
		row=0,
		column=0,
		rowspan=1,
		columnspan=9,
		padx=0,
		pady=0,
		sticky="news"
	)

	# Create a listbox to display the input items
	listbox = tk.Listbox(
		window,
		bg="#33217C",
		font=('Arial', 16),
		fg="#F7F5FF"
	)
	listbox.grid(
		row=1,
		column=0,
		rowspan=6,
		columnspan=9,
		padx=10,
		pady=10,
		sticky="news"
	)

	# insert header
	listbox.insert("end", f"Write something to the server! Commands start with '/'.")
	listbox.itemconfig("end", bg="#FF174D")

	# create the input box
	input_box = tk.Entry(
		window,
		bg="#33217C",
		font=('Arial', 16),
		fg="#F7F5FF"
	)
	input_box.grid(
		row=7,
		column=0,
		rowspan=1,
		columnspan=9,
		padx=10,
		pady=0,
		sticky="news"
	)

	# create the button
	clear_button = tk.Button(
		window,
		text="Clear screen",
		bg="#6340F3",
		font=('Calibri', 18, 'bold'),
		fg="#F9F9F9",
		command=lambda: listbox.delete(1, tk.END)
	)
	clear_button.grid(
		row=8,
		column=3,
		rowspan=3,
		columnspan=3,
		padx=10,
		pady=10,
		sticky="news"
	)

	# make resizes look good
	for i in range(9):
		window.columnconfigure(i, weight=1)
	for i in range(9):
		window.rowconfigure(i, weight=1)

	return window, title_label, listbox, input_box, clear_button


def check_portsUDP(start_port: int, end_port: int) -> None:
	"""
	1. sends a broadcast to every port in the range specified
	2. listens to responses in broadcast
	:param start_port: spamming starts from this port number
	:param end_port: spamming ends at this port number
	:return: None. the global ip and port are updated.
	"""
	global tcp_port, ip

	if tcp_port:
		return

	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
	sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
	sock.settimeout(0.0125)  # set a timeout for the connection attempt

	for port in range(start_port, end_port):
		try:
			# sock.connect(('<broadcast>', port))
			sock.sendto(b"Requesting UDP connection.", ('<broadcast>', port))  # send a test message to the port
			response = sock.recvfrom(1024)  # receive any response from the port

			# check if response is from the server and not echo
			if response and b"Requesting UDP connection." not in response:
				ip, tcp_port = response[0].decode().split('|')  # the server will return its tcp socket port
				tcp_port = int(tcp_port)
				sock.close()  # close the socket connection
				return

		except socket.error:
			pass  # port is closed or unreachable

	sock.close()


def scan_for_server_ipNport() -> tuple:
	"""
	perform a try broadcasting on every port to get servers ip address and port
	:return: ip address and tcp port of server if found. both will be 'None' if not.
	"""
	# (not a dos)
	global tcp_port, ip

	threads = []
	for start_port in range(40000, 65536, 100):
		end_port = min(start_port + 100, 65536)
		threads.append(threading.Thread(target=check_portsUDP, args=(start_port, end_port,)))

	for t in threads:
		t.start()

	for t in threads:
		t.join()

	if not tcp_port:
		raise ConnectionError("Could not find an active TCP server port.")
	else:
		return ip, tcp_port


def connect_socketTCP(ip: str, tcp_port: int) -> socket.socket():
	"""
	attempting to connect to the socket whose details the client received.
	:param ip: ip address of the server
	:param tcp_port: port of the server
	:return: socket if connection was successful None otherwise
	"""
	# Create a socket instance
	socketObject = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	try:
		socketObject.connect((ip, tcp_port))
	except socket.error:
		print(f"No socket found at {tcp_port}")
		return
	return socketObject


def gain_symmetric_key(socketObject: socket.socket) -> int:
	"""
	completes the handshake with the server and acquires a shared symmetric key using DH
	:param socketObject: client's socket
	:return: shared symmetric key
	"""
	# create public key
	private_key = int(random.random() * 10 ** 32)
	public_key = cryptography.DH.public_key(private_key)

	# send the public key to server
	msgBytes = str.encode(str(public_key))
	socketObject.sendall(msgBytes)

	# wait for server's public key
	while True:
		data = socketObject.recv(1024)
		data = data.decode()
		if data:
			other_public_key = int(data)
			break

	# create shared secret
	symmetric_key = cryptography.DH.shared_secret(other_public_key, private_key)

	return symmetric_key


def send_string(conn: socket.socket(), msg: str, key: int) -> None:
	"""
	sends a string to server after encrypting it
	:param conn: client's socket
	:param msg: message string
	:param key: symmetric encryption key
	:return: None
	"""
	cipher_text = str.encode(cryptography.AES128.encrypt(msg, key))
	conn.sendall(cipher_text)


def get_input(event, socketObject: socket.socket, input_box, listbox, symmetric_key: int) -> None:
	"""
	performs input check for user's input, and if passed sends it to the server
	:param event: clicking 'enter'
	:param socketObject: client's socket
	:param input_box: window's input box object
	:param listbox: window's input box object
	:param symmetric_key: symmetric encryption key
	:return: None
	"""
	user_input = input_box.get()
	english_flag = list(filter(lambda c: ord(c) < 256, user_input)) if user_input else 1
	if english_flag:  # make sure all chars are in english
		if user_input:
			listbox.insert("end", f"Client ({datetime.now().strftime('%H:%M:%S')}): {user_input}")
			# send to server
			send_string(socketObject, user_input, symmetric_key)
	else:
		listbox.insert("end", "Enter a valid message!")
		listbox.itemconfig("end", bg="#FF174D")
	input_box.delete(0, "end")
	listbox.see(tk.END)


def recv_data(window, listbox, socketObject: socket.socket, symmetric_key: int) -> None:
	"""
	daemon thread that receives data from server and updates the user's gui
	:param window: tkinter Tk object
	:param listbox: window's list box object
	:param socketObject: client's socket
	:param symmetric_key: symmetric encryption key
	:return: None
	"""
	try:
		while True:
			data = socketObject.recv(1024)
			data = data.decode('utf-8')
			if data:

				plain_text = cryptography.AES128.decrypt(data, symmetric_key)
				plain_text = plain_text.replace('N@L', '\n')  # changing back to new line meta character after decryption

				for subMsg in plain_text.split('\n'):
					listbox.insert("end", f"Server ({datetime.now().strftime('%H:%M:%S')}): {subMsg}")
					listbox.itemconfig("end", fg="#9CF94B")
					listbox.see(tk.END)

				# close the connection because of a code
				if "It\'s been such a good time :(" in plain_text:
					break

	except (ConnectionResetError, OSError, TimeoutError):
		print('Connection was quit unexpectedly or due to timeout.')

	finally:
		# close everything before quitting
		time.sleep(2)
		window.destroy()
		send_string(socketObject, "/close", symmetric_key)
		socketObject.close()
		print("Connection and gui closed.")
		quit()


def main() -> None:
	"""
	main function. creates and run the connection and gui
	:return: None
	"""
	# connect to tcp socket and handshake
	for i in range(3):  # try 3 times as UDP is unreliable
		try:
			ip, tcp_port = scan_for_server_ipNport()
			socketObject = connect_socketTCP(ip, tcp_port)
			print("Established connection with TCP socket!")
			symmetric_key = gain_symmetric_key(socketObject)
			print(f"Attempt {i + 1}: Completed handshake with TCP socket. Symmetric key: {hex(symmetric_key)[2:34]}")
			break

		except Exception as e:
			print(f"Attempt {i+1}: Could not complete connection or handshake with TCP socket due to {e}")
			if i < 2:
				continue
			else:
				return

	# create gui
	window, title_label, listbox, input_box, clear_button = create_gui()

	# detect input from input_box
	input_box.bind("<Return>", lambda event: get_input(event, socketObject, input_box, listbox, symmetric_key))

	# receive data from server
	threading.Thread(target=recv_data, daemon=True, args=(window, listbox, socketObject, symmetric_key,)).start()

	window.mainloop()

	send_string(socketObject, "/close", symmetric_key)
	socketObject.close()
	quit()


if __name__ == "__main__":
	# defining global vars
	tcp_port = None
	ip = None
	# call main function
	main()
