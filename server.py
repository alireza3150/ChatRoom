import socket
import threading
import base64

# from Crypto.Cipher import AES
# from Crypto.Random import get_random_bytes
# from Crypto.Util.Padding import pad
# from Crypto.Util.Padding import unpad


# key = get_random_bytes(32)
# iv = get_random_bytes(16)

host = '127.0.0.1'
port = 15001

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((host, port))
server.listen()

clients = []
nicknames = []
passwords = []

actives = []
user_name_active = []

def broadcast(message):
    for cli in actives:
        cli.send(message)


def broadcast_1(li, message):
    for cli in li:
        cli.send(message)


def handle(client):
    cli = client
    while True:
        try:
            msg = message = base64.b64decode(client.recv(1024))

            if msg.decode('ascii').split(' ')[1] == 'Hello':
                user = msg.decode('ascii').split(' ')[2]
                if user in nicknames and user == nicknames[clients.index(client)]:
                    if user in user_name_active:
                        actives.remove(client)
                        user_name_active.remove(user)
                        broadcast(base64.b64encode(f'{user} left the chat'.encode('ascii')))
                        print(f'{user} left the chat')
                        actives.append(client)
                        user_name_active.append(user)
                        client.send(base64.b64encode(f'Hi {user}, welcome to the chat room!'.encode('ascii')))
                        broadcast(base64.b64encode(f'{user} join the chat room!.'.encode('ascii')))
                        print(f'{user} joined the chat')

                    else:
                        actives.append(client)
                        user_name_active.append(user)
                        client.send(base64.b64encode(f'Hi {user}, welcome to the chat room!'.encode('ascii')))
                        broadcast(base64.b64encode(f'{user} join the chat room!.'.encode('ascii')))
                        print(f'{user} joined the chat')
                else:
                    client.send(base64.b64encode('Invalid username.'.encode('ascii')))

            elif msg.decode('ascii').split(':')[1] == ' Please send the list of attendees.':
                name_list = ', '.join(user_name_active)
                client.send(base64.b64encode(f'Here is the list of attendees:\n{name_list}'.encode('ascii')))

            elif client in actives and msg.decode('ascii').split(': ')[0] == 'public message':
                nickname = msg.decode('ascii').split(': ')[1]
                message_body = f'Public message from {nickname}, length={len(msg.decode('ascii').split(': ')[2].encode('utf-8'))}\n'
                message_2 = f'{msg.decode('ascii').split(': ')[2]}'
                broad = message_body + message_2
                broadcast(base64.b64encode(broad.encode('ascii')))
                print(f'{broad}\n')

            elif client in actives and msg.decode('ascii').split(': ')[0] == 'private message':
                nickname = msg.decode('ascii').split(' ')[3][:-1]
                target = msg.decode('ascii').split(' ')[2].split(',')
                cli_target = []
                length = len(msg.decode('ascii').split(': ')[2].encode('utf-8'))
                message_body = f'Private message, length={length} from {nickname} to {','.join(target)}:\n'
                message_2 = f'{msg.decode('ascii').split(': ')[2]}'
                broad = message_body + message_2
                for i in target:
                    if i in nicknames:
                        index = nicknames.index(i)
                        cli = clients[index]
                        if cli in actives:
                            cli_target.append(cli)
                broadcast_1(cli_target, base64.b64encode(broad.encode('ascii')))
                print(f'{broad}\n')

            elif client in actives and msg.decode('ascii').split(': ')[1] == 'Bye':
                if client in actives:
                    actives.remove(client)
                    user_name_active.remove(nicknames[clients.index(client)])
                    client.send(base64.b64encode('You left the chat room!'.encode('ascii')))
                    broadcast(base64.b64encode(f'{nicknames[clients.index(client)]} left the chat room!'.encode('ascii')))
                    print(f'{nicknames[clients.index(client)]} left the chat room!\n')
                else:
                    client.send(base64.b64encode('You are not on chat room'.encode('ascii')))
            else:
                if client not in actives:
                    client.send(base64.b64encode('You are not active please send <Hello> first.'.encode('ascii')))
                else:
                    chats = msg.decode('ascii')
                    broadcast(base64.b64encode(message))
                    print(f'{chats}')
        except (ConnectionAbortedError, ConnectionResetError):
            print("Client disconnected unexpectedly.")
            clients.remove(client)
            user_name_active.remove(nicknames[clients.index(client)])
            if client in clients:
                actives.remove(client)
                broadcast(base64.b64encode(f'{nicknames[clients.index(client)]} left the chat room!'.encode('ascii')))
            break

        except Exception as e:
            print(f"Unexpected error handling client: {e}")
            clients.remove(client)

            if client in clients:
                user_name_active.remove(nicknames[clients.index(client)])
                actives.remove(client)
                broadcast(
                    base64.b64encode(f'{nicknames[clients.index(client)]} left the chat room (error)!'.encode('ascii')))
            break


def recive():
    while True:
        client, address = server.accept()
        print(f'Connected with {str(address)}')

        client.send(base64.b64encode('NICK'.encode('ascii')))

        requests = base64.b64decode(client.recv(1024)).decode('ascii')

        if requests.startswith('Registration'):
            sign = requests.split(' ')
            if sign[1] not in nicknames:
                # clients.append(client)
                nicknames.append(sign[1])
                passwords.append(sign[2])
                index = nicknames.index(sign[1])
                clients.insert(index, client)

                client.send(base64.b64encode('ok'.encode('ascii')))

                print(f'{sign[1]} is now registered\n')
            else:

                client.send(base64.b64encode('Someone has this username already!'.encode('ascii')))

                client.close()
                continue

        elif requests.startswith('Login'):
            sign = requests.split(' ')
            if sign[1] in nicknames:

                client.send(base64.b64encode('ok'.encode('ascii')))
                base64.b64decode(client.recv(1024)).decode('ascii')
                # password = encryption(passwords[nicknames.index(sign[1])])
                client.send(base64.b64encode(passwords[nicknames.index(sign[1])].encode('ascii')))

                send = base64.b64decode(client.recv(1024)).decode('ascii')

                pass_index = nicknames.index(sign[1])
                if send == 'ok':
                    if sign[1] in user_name_active:
                        actives.remove(clients[nicknames.index(sign[1])])
                        user_name_active.remove(nicknames[nicknames.index(sign[1])])

                        broadcast(base64.b64encode(f'{sign[1]} left the chat!'.encode('ascii')))

                        print(f'{sign[1]} is left the chat!\n')

                        (clients[nicknames.index(sign[1])].
                         send(base64.b64encode('someone is now logged in and close you!'.encode('ascii'))))
                        clients[nicknames.index(sign[1])].close()

                        clients.insert(pass_index, client)

                        client.send(base64.b64encode('You are logged in'.encode('ascii')))

                        print(f'{sign[1]} is now logged')
                    else:
                        (clients[nicknames.index(sign[1])].
                         send(base64.b64encode('someone is now logged in and close you!'.encode('ascii'))))
                        # clients[nicknames.index(sign[1])].close()

                        clients.insert(pass_index, client)

                        client.send(base64.b64encode('You are logged in'.encode('ascii')))

                        print(f'{sign[1]} is now logged')

                else:
                    client.send(base64.b64encode('Invalid password!'.encode('ascii')))
                    client.close()
                    continue
            else:
                client.send(base64.b64encode('Invalid username'.encode('ascii')))
                client.close()
                continue

        thread = threading.Thread(target=handle, args=(client,))
        thread.start()

# def encryption(code):
#     data = code.encode()
#     cipher = AES.new(key, AES.MODE_CBC, iv)
#     padded_data = pad(data, AES.block_size)
#     return cipher.encrypt(padded_data)


print("Server is listening...")
recive()

