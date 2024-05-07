import socket
import threading
import base64

# from Crypto.Cipher import AES
# from Crypto.Random import get_random_bytes
# from Crypto.Util.Padding import pad
# from Crypto.Util.Padding import unpad
#
# key = get_random_bytes(32)
# iv = get_random_bytes(16)

request = input("Enter your request: ")

nickname = request.split(' ')[1]

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(('127.0.0.1', 15001))

stop_thread = False


def recive():
    while True:
        global stop_thread
        if stop_thread:
            break
        try:
            message = base64.b64decode(client.recv(1024)).decode('ascii')

            if message == 'NICK':
                client.send(base64.b64encode(request.encode('ascii')))

                if request.startswith('Registration'):
                    next_message = base64.b64decode(client.recv(1024)).decode('ascii')
                    if next_message == 'ok':
                        print('You are registered')
                    else:
                        print(next_message)
                        client.close()
                        stop_thread = True

                elif request.startswith('Login'):

                    next_message = base64.b64decode(client.recv(1024)).decode('ascii')

                    if next_message == 'ok':
                        password = input('Enter your password: ')

                        client.send(base64.b64encode(password.encode('ascii')))

                        next_message_1 = base64.b64decode(client.recv(1024)).decode('ascii')
                        # true_password = decryption(next_message_1)
                        # print(true_password)
                        if next_message_1 == password:
                            client.send(base64.b64encode('ok'.encode('ascii')))
                            recive = base64.b64decode(client.recv(1024)).decode('ascii')
                            print(recive)
                        else:
                            # print(next_message_1)
                            client.close()
                            stop_thread = True
                    else:
                        print(next_message)
                        client.close()
                        stop_thread = True

            else:
                print(message)

        except:
            print("An error occurred")
            client.close()
            break


def write():
    while True:
        if stop_thread:
            break
        message = f'{nickname}: {input('')}'

        if message.split(': ')[1].startswith('public message'):
            length = int(message.split(': ')[1].split(', ')[1].split('=')[1][:-1])
            message_body = f'{nickname}: {input('')}'
            if len(message_body.split(': ')[1].encode("utf-8")) == length:
                send = f'public message: {message_body}'
                client.send(base64.b64encode(send.encode('ascii')))
            else:
                print("your message too long please try again")

        elif message.split(': ')[1].startswith('private message'):
            length_2 = int(message.split(': ')[1].split(', ')[1].split('=')[1].split(' ')[0])
            user_target = message.split(': ')[1].split(', ')[1].split(' ')[2][:-1]
            message_body = f'{nickname}: {input('')}'

            if len(message_body.split(': ')[1].encode("utf-8")) == length_2:
                send = f'private message: {user_target} {message_body}'
                client.send(base64.b64encode(send.encode('ascii')))
            else:
                print("your message too long or short")

        else:

            client.send(base64.b64encode(message.encode('ascii')))



# def decryption(code):
#     cipher = AES.new(key, AES.MODE_CBC, iv)
#     decrypted_data = cipher.decrypt(code)
#     return unpad(decrypted_data, AES.block_size).decode()


recvice_thread = threading.Thread(target=recive)
recvice_thread.start()

write_thread = threading.Thread(target=write)
write_thread.start()


