'''
Description: Take input requests from a TCP client to generate hash and 
            send it back to the client.

Steps:
2) The server will respond w/ the hash of the segment.
    a) Acknowledgement
        Type=0x2    i   Length      Data(length)
        1. Type: A 4-bit value in network byte order that is set to the value 2. 
        2. Length: A 4-byte integer value in network byte order that denotes the 
                total length of all HashResponses. This should be equal to 40*S.
        3. Fields “i” and “Data” must be 0, and an empty 32-byte payload respectively.
    b) HashResponse
        Type=0x4    i   Length      Hash_of_i(32bytes)
        1. Type: A 4-bit value in network byte order that is set to the value 4.
        2. i: A 4-byte integer value in network byte order that denotes the one-based 
           index of the response. That is, the first HashResponse should have this set to 1, 
           while the last HashResponse should have this set to N.
        3. Field “Length” must be 32, as 32-bytes of data is included this packet.
        4. Hash_of_i: A 32-byte (256-bit) value that corresponds to the hash of the data contained
           in the ith HashRequest sent by the client.

Constraint: Must be able to handle more than 1 client concurrently.
'''


import struct
import sys
import socket
import select
import hashlib


INITIALIZATION_TYPE_VAL = 1
ACKNOWLEDGEMENT_TYPE_VALUE = 2
HASH_REQUEST_TYPE_VAL = 3
HASH_RESPONSE_TYPE_VALUE = 4
MULTIPLIER = 40


def create_struct(short_int1, long_int1, long_int2, str_32_byte):
    # This function will be used to create a universal struct object
    message = struct.pack('!HLL32s', short_int1, long_int1, long_int2, str_32_byte)
    return message
    

def open_struct(struct_obj):
    # This function will be used to open a universal struct object
    message = struct.unpack('!HLL32s', struct_obj)
    return message  # Returns array [short, long, long, 32-byte string]


def create_acknowledgement(input_n):
    # This function retrieves the S value from the initialization message
    # Then, return acknowledgement message
    empty_binary = b'\x00' * 32 # empty 32-byte payload
    message = create_struct(ACKNOWLEDGEMENT_TYPE_VALUE, 0, socket.htonl(input_n) * MULTIPLIER, empty_binary) # TODO: ASK about converting it to network again to multiply, whats the point of converting to host initially?
    return message


def check_initialization(encoded_data):
    try:
        initial_message = open_struct(encoded_data)
        num_hash_requests = socket.ntohl(initial_message[1])  # Block sizes this client will send
        type_val = socket.ntohs(initial_message[0])
        if type_val != socket.ntohs(INITIALIZATION_TYPE_VAL):       # TODO: Ask if this is correct, or should i check it w/out the ntohs
            print("SERVER: Invalid Type Value")
            return False
        return num_hash_requests
    except struct.error as e:
        print("SERVER: Invalid Data Format - ", e)
        return False
    
def check_hash_request(encoded_data):
    try:
        initial_message = open_struct(encoded_data)
        type_val = socket.ntohs(initial_message[0])
        if type_val != socket.ntohs(HASH_REQUEST_TYPE_VAL):
            print("SERVER: Invalid Type Value")
            return False 
        return initial_message # Struct Object
    except struct.error as e:
        print("SERVER: Invalid Data Format - ", e)
        return False


def get_hashed_data(hash_request):
    # This function will receive an unpacked struct representing our hash request
    # Then, return hashed data and hash response
    
    # Extract variables
    request_type = hash_request[0]  # HashRequest Type
    request_i = hash_request[1]  # HashRequest i
    request_len = hash_request[2]  # HashRequest Length
    request_payload = hash_request[3] + hash_salt.encode()  # HashRequest Data + UTF-8 Encoded Salt

    hash_and_salt = hashlib.sha512(request_payload).hexdigest()
    #request_i = TODO: maybe this is the i for the request?
    return create_struct(HASH_RESPONSE_TYPE_VALUE, request_i, len(hash_and_salt), hash_and_salt.encode())


def start_server(port):
    # This function will create our TCP Server Socket, start listening, then return the Socket Object

    tcp_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_server_socket.setblocking(0)  # Allow multiple connections
    tcp_server_socket.bind(("127.0.0.1", port))  # Start listening!
    tcp_server_socket.listen(10)  # 10 is the max number of queued connections allowed
    return tcp_server_socket


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    if len(sys.argv) < 5:
        print('Usage : "python server.py -p server_port -s hash_salt"\n[server_port: port number that server will bind and listen on]\n[hash_salt: a salt value that server will use in computing hash]')
        sys.exit(2)

    # Create dictionary with keys being the flags [-p, -s]
    args = {}
    for flag, value in zip(sys.argv[1::2], sys.argv[2::2]):
        args[flag] = value
    
    if '-p' not in args or '-s' not in args:
        print("Error: Missing required options.")
        sys.exit(2)

    # Variables we need
    server_port = int(args['-p'])  # Extract server port from command line arguments
    hash_salt = args['-s']  # Extract salt value from command line arguments

    server_socket = start_server(server_port)
    clients = {server_socket}
    n_sizes = {}
    print("Server listening...")

    while clients:
        readable, _, exceptional = select.select(clients, [], clients)

        for s in readable:
            if s is server_socket:
                # Client connects to welcoming socket
                client_socket, addr = s.accept()
                client_socket.setblocking(0)
                print("Received a connection from: ", addr)

                # Add new client_socket to list of clients to monitor
                clients.add(client_socket)
            else:
                try:
                    # Initialization
                    if s not in n_sizes:
                        message = s.recv(1024)
                        print("Received initialization: ", message)
                        if message:
                            num_hash_requests = check_initialization(message)

                            if num_hash_requests:
                                n_sizes[s] = num_hash_requests

                                # Respond with Acknowledgement
                                acknowledgment_message = create_acknowledgement(num_hash_requests)
                                s.sendall(acknowledgment_message)
                                print("Acknowledgment sent.")
                        # No data
                        else:
                            clients.remove(s)
                            s.close()
                    # Hash-Request
                    else:
                        hash_request = check_hash_request(s.recv(n_sizes[s]))
                        print("Hash Request received: ", hash_request)

                        if hash_request:
                            hash_response = get_hashed_data(hash_request)
                            s.sendall(hash_response)
                            print("Hash Response sent.")
                        # No more data in file
                        else:
                            del n_sizes[s]
                            clients.remove(s)
                            s.close()
                except OSError as e:
                    print(f"Error {e} with socket: {s}")
                    clients.remove(s)
                    s.close()
        for s in exceptional:
            clients.remove(s)
            s.close()