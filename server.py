# modules
import socket
import threading
import random
from datetime import datetime
import time
import re
import math
import hashlib
# utils
import cryptography


# this is server side


def gain_symmetric_key(clientConnection: socket.socket) -> int:
	"""
	completes the handshake with the server and acquires a shared symmetric key using DH
	:param clientConnection: server's socket
	:return: shared symmetric key
	"""
	# create public key
	private_key = int(random.random() * 10 ** 32)
	public_key = cryptography.DH.public_key(private_key)

	# wait for client's public key
	while True:
		data = clientConnection.recv(1024)
		data = data.decode()
		if data:
			other_public_key = int(data)
			break

	# send the public key to server
	msgBytes = str.encode(str(public_key))
	clientConnection.send(msgBytes)

	# create shared secret
	symmetric_key = cryptography.DH.shared_secret(other_public_key, private_key)
	return symmetric_key


def update_log(msg: str) -> None:
	"""
	updating the server admin log, adding time and printing it
	:param msg: message to store in log
	:return: None
	"""
	global server_log
	msg = f"{datetime.now().strftime('%H:%M:%S')} {msg}"
	server_log += f"\n{msg}"
	print(msg)


def run_UDPsocket() -> None:
	"""
	runs the UDP socket that listens to broadcasts that ask for the servers details.
	it opens a TCP socket in a daemon thread for the connection and broadcasts back its details.
	:return: None
	"""
	global kill_switch

	try:
		# udp server that responds the server ip and tcp port of the new socket

		# create socket object
		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
		s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
		# bind socket to a free port
		s.bind(('', 0))
		update_log("UDP socket is running and accepting connections")

		while not kill_switch:
			# receive incoming data
			data, addr = s.recvfrom(1024)
			if data == b"Requesting UDP connection.":

				# create new socket
				newS = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

				newS.bind((socket.gethostname(), 0))

				update_log(f"UDP socket created a TCP socket at ({newS.getsockname()[0]} , {newS.getsockname()[1]})")

				# create thread for socket
				threading.Thread(target=run_TCPsocket, daemon=True, args=(newS,)).start()

				# send ip+port to the client
				msgBytes = str.encode(f"{newS.getsockname()[0]}|{newS.getsockname()[1]}")
				s.sendto(msgBytes, ('<broadcast>', addr[1]))

	except Exception as e:
		# close the socket
		update_log(f"UDP server was closed due to {e}")
		s.close()
		return
	finally:
		# close the socket
		update_log(f"UDP server was closed due to kill switch activation")
		s.close()


def send_string(conn: socket.socket, msg: str, key: int) -> None:
	"""
	sends a string to client after encrypting it
	:param conn: connection's socket
	:param msg: message string
	:param key: symmetric encryption key
	:return: None
	"""
	msg = msg.replace('\n', 'N@L')  # changing the new line meta character before encryption
	cipher_text = str.encode(cryptography.AES128.encrypt(msg, key))
	conn.send(cipher_text)


def correct_password(guess: str) -> bool:
	"""
	compares the admin password hash to the client's guess hash
	:param guess: password string provided by clients
	:return: whatever the guess is correct or not
	"""
	global admin_password_hash
	hash_object = hashlib.sha256(str.encode(guess))
	# if hashes are the same
	return admin_password_hash == hash_object.hexdigest()


def quadroots(a: float, b: float, c: float) -> str:
	"""
	calculates the roots of a quadratic equation provided by the client:
	ax^2 + bx + c = 0
	:param a: ax^2
	:param b: bx
	:param c: c
	:return: string with the roots
	"""
	if a == 0:
		if b == 0:
			if c == 0:
				return "The equation is degenerate"
			else:
				return "The equation has no roots"
		else:
			root = -c / b
			return f"The root is {root:.2f}"

	else:
		discriminant = b ** 2 - 4 * a * c

		# check if the discriminant is negative
		if discriminant < 0:
			sqrt_discriminant = math.sqrt(abs(discriminant))
			real_part = -b / (2 * a)
			imag_part = sqrt_discriminant / (2 * a)
			return f"The roots are {real_part:.2f} + {imag_part:.2f}i and {real_part:.2f} - {imag_part:.2f}i "

		# calculate the roots
		sqrt_discriminant = math.sqrt(discriminant)
		root1 = (-b + sqrt_discriminant) / (2 * a)
		root2 = (-b - sqrt_discriminant) / (2 * a)
		return f"The roots are {root1:.2f} and {root2:.2f}"


def run_TCPsocket(serverTCPSocket: socket.socket) -> None:
	"""
	runs a TCP socket that communicates with 1 client and provides the desired services
	:param serverTCPSocket: connection socket
	:return: None
	"""
	global kill_switch

	# listen for incoming connection
	serverTCPSocket.listen(1)
	# accept incoming connection
	conn, addr = serverTCPSocket.accept()
	conn.setblocking(0)
	update_log(f"TCP socket received a new connection from {addr}")

	# handshake with client
	try:
		symmetric_key = gain_symmetric_key(conn)
		update_log(f"TCP socket completed handshake with {addr}.")
	except Exception as e:
		update_log(f"Could not complete handshake with {addr} due to {e}. Closing connection")
		conn.close()
		return

	# session loop
	try:

		while not kill_switch:

			# define a timeout
			start_time = time.time()
			noted_flag = False

			while True:

				if kill_switch:
					break

				# check for timeouts
				if time.time() - start_time > (timeout := 120):  # 2 minutes have passed
					# notify client
					send_string(conn, "You have exceeded your timeout and be disconnected. It's been such a good time :(", symmetric_key)
					conn.close()
					update_log(f"TCP socket assigned to {addr} is closed due to timeout")
					return

				if time.time() - start_time > timeout / 2 and not noted_flag:
					# notify client
					noted_flag = True
					send_string(conn, f"You have exceeded half your timeout and be disconnected in {timeout / 2} seconds if you remain inactive!", symmetric_key)

				# try to recv data
				try:
					data = conn.recv(1024)
				except socket.error as e:
					if e.errno == socket.errno.EWOULDBLOCK:  # no data right now, continue
						continue
					else:  # something went wrong
						break

				data = data.decode('utf-8')
				if data:
					plain_text = cryptography.AES128.decrypt(data, symmetric_key)

					# the server will return the message received
					if '/echo' in plain_text:
						# input check
						if re.match(r"^\/echo .+", plain_text):
							# send the echo to the client
							send_string(conn, f"\'{plain_text[6:]}\'", symmetric_key)
						else:
							send_string(conn, "Wrong use of the \'/echo\' command.\nThe syntax is \'/echo <message>\'", symmetric_key)

					# the server will return the current server time
					elif '/time' in plain_text:
						# input check
						if '/time' == plain_text:
							# send the server time to client
							send_string(conn, f"The server time is: {time.ctime(time.time())}", symmetric_key)
						else:
							send_string(conn, "Wrong use of the \'/time\' command.\nThe syntax is \'/time\'", symmetric_key)

					# the server will close this connection
					elif '/close' in plain_text:
						# input check
						if '/close' == plain_text:
							# notify client
							send_string(conn, "Our connection will be terminated now. It's been such a good time :(", symmetric_key)
							conn.close()
							update_log(f"TCP socket assigned to {addr} is closed due to request")
							return
						else:
							send_string(conn, "Wrong use of the \'/close\' command.\nThe syntax is \'/close\'", symmetric_key)

					# the server will disconnect everyone
					elif '/shutdown' in plain_text:
						# input check
						if re.match(r"^\/shutdown .+", plain_text):
							# check if provided password is correct
							if correct_password(plain_text[10:]):
								# notify client
								send_string(conn, "Passed admin verification. Committing server shutdown.", symmetric_key)
								kill_switch = True
								update_log(f"TCP socket assigned to {addr} activated server termination.")

							else:
								send_string(conn, "Incorrect password. Make sure you have the correct admin password.", symmetric_key)
						else:
							send_string(conn, "Wrong use of the \'/shutdown\' command.\nThe syntax is \'/shutdown <admin_password>\'", symmetric_key)

					# the server will send the admin log
					elif '/log' in plain_text:
						# input check
						if re.match(r"^\/log .+", plain_text):
							# check if provided password is correct
							if correct_password(plain_text[5:]):
								# notify client
								global server_log
								send_string(conn, f"Passed admin verification.\nServer log:{server_log}", symmetric_key)
								update_log(f"TCP socket assigned to {addr} requested server log.")

							else:
								send_string(conn, "Incorrect password. Make sure you have the correct admin password.", symmetric_key)
						else:
							send_string(conn, "Wrong use of the \'/log\' command.\nThe syntax is \'/log <admin_password>\'", symmetric_key)

					# the server will solve the expression received
					elif '/calculator' in plain_text:
						# input check
						if re.match(r"^\/calculator .+", plain_text):
							plain_text = plain_text[12:].replace('^', '**')
							try:
								ans = str(eval(plain_text))
								send_string(conn, f"Ans = {ans}", symmetric_key)

							except ZeroDivisionError:  # answer is nan because of zero division
								send_string(conn, f"Ans = NaN", symmetric_key)

							except:  # invalid expression
								send_string(conn, "Invalid expression. Note you can only use (),+,-,*,/,^ and keep every brackets closed.", symmetric_key)

						else:
							send_string(conn, "Wrong use of the \'/calculator\' command.\nThe syntax is \'/calculator <arithmetic_expression>\'", symmetric_key)

					# the server will return the roods of a quadratic equation
					elif '/quadroots' in plain_text:
						# input check
						if re.match(r"^\/quadroots -?\d+(\.\d+)? -?\d+(\.\d+)? -?\d+(\.\d+)?$", plain_text):
							ans = quadroots(float(plain_text.split()[1]), float(plain_text.split()[2]), float(plain_text.split()[3]))
							# send back the roots
							send_string(conn, ans, symmetric_key)

						else:
							send_string(conn, "Wrong use of the \'/quadroots\' command.\nThe syntax is \'/quadroots <param_A> <param_B> <param_C>\'", symmetric_key)

					# the server will return a list of all services
					elif '/help' in plain_text:
						# input check
						if '/help' == plain_text:
							help_string = "/echo - Server will return the desired message\n" \
										  "/time - Server will return the current server time\n" \
										  "/close - Close the connection with the server\n" \
										  "/shutdown - Request a server shutdown\n" \
										  "/calculator - Server will return the answer of an arithmetic expression\n" \
										  "/quadroots - Server will return the roots of a quadratic equation\n" \
										  "/log - Request the server admin log\n" \
										  "/help - Server will return a description of all services"
							send_string(conn, help_string, symmetric_key)

						else:
							send_string(conn, "Wrong use of the \'/help\' command.\nThe syntax is \'/help\'", symmetric_key)

					# handle general cases
					else:
						send_string(conn, "Unknown command. Try typing \'/help\'!", symmetric_key)

					break

		# notify client
		send_string(conn, "The server and our connection will be terminated now. It\'s been such a good time :(", symmetric_key)
		conn.close()
		return

	except Exception as e:
		conn.close()
		update_log(f"TCP socket assigned to {addr} is closed due to {e}")
		return


if __name__ == "__main__":
	# defining global vars
	kill_switch = False
	server_log = ""
	admin_password_hash = "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3" # can be changed to any hash

	threading.Thread(target=run_UDPsocket, daemon=True, args=()).start()

	while True:
		if kill_switch:
			# close the server if kill switch was activated
			time.sleep(2)
			update_log('Server closed.')
			quit()
