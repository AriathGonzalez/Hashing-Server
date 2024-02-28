'''
Description: Has a file and wants to obtain the hashes for various segments
            of the data inside the file. 

Steps: 
1) The client will send a msg to the server for each segment.
    a) Initialization
        Type=0x1    S   Length      Data(length)

        1. Type: A 4-bit value in network byte order that is set to the val 1.
        2. S: A 4-byte integer value in network byte order that corresponds to 
           the size of each HashRequest Segment that the client will send to the server
        3. The other fields must be 0, and an empty 32-byte payload respectively.

    b) HashRequest
        Type=0x3    i   Length      Data(length)
        1. Type: A 4-bit value in network byte order that is set to the value 3.
        2. i: A 4-byte integer value in network byte order that denotes the zero-based 
           index of the request. That is, the first HashRequest should have this set to 0, 
           while the last HashRequest should have this set to N - 1.
        3. Length: A 4-byte integer value in network byte order that denotes the length of
           the Data payload in number of bytes. (You can assume something on your own)
        4. Data: A payload that holds the data segment to be hashed (of length defined in #2
           above).
3) The client converts each hash into a hexadecimal string representation
and prints it to the console.
'''


import struct
import sys
import socket
import os


INITIALIZATION_TYPE_VAL = 1
ACKNOWLEDGEMENT_TYPE_VALUE = 2
HASH_REQUEST_TYPE_VAL = 3
HASH_RESPONSE_TYPE_VALUE = 4


def create_struct(short_int1, long_int1, long_int2, str_32_byte):
    """
    Creates a universal struct object.

    Args:
        short_int1 (int): First short integer.
        long_int1 (int): First long integer.
        long_int2 (int): Second long integer.
        str_32_byte (bytes): 32-byte string.

    Returns:
        bytes: Struct object.
    """

    message = struct.pack('!HLL32s', short_int1, long_int1, long_int2, str_32_byte)
    return message


def open_struct(struct_obj):
    """
    Unpacks a universal struct object and returns its components.

    Args:
        struct_obj (bytes): Struct object to be unpacked.

    Returns:
        tuple: Tuple containing short integer, two long integers, and a 32-byte string.
    """

    message = struct.unpack('!HLL32s', struct_obj)
    return message  # Returns array [short, long, long, 32-byte string]


def create_initialization(hash_requests):
    """
    Creates an initialization message with given hash requests to 
    send to the server using struct. Then, returns the message.

    Args:
        hash_requests (int): Number of hash requests.

    Returns:
        bytes: Initialization message.
    """

    empty_binary = b'\x00' * 32 # empty 32-byte payload
    message = create_struct(INITIALIZATION_TYPE_VAL, hash_requests, 0, empty_binary)
    return message


def create_hash_request(hash_count, current_block):
    """
    Creates a hash request message. Then, returns the 
    message as a struct object.

    Args:
        hash_count (int): Hash count.
        current_block (str): Current block data.

    Returns:
        bytes: Hash request message.
    """

    hash_count = socket.ntohs(hash_count)
    block_len = len(current_block)
    struct_hash_message = create_struct(HASH_REQUEST_TYPE_VAL, hash_count, block_len, current_block.encode())

    return struct_hash_message


def check_acknowledgement(encoded_data):
    """
    Checks the acknowledgement message.

    Args:
        encoded_data (bytes): Encoded data to be checked.

    Returns:
        bool or int: False if invalid message, otherwise returns the length from acknowledgment message.
    """

    try:
        initial_message = open_struct(encoded_data)
        type_val = socket.ntohs(initial_message[0])
        if type_val != socket.ntohs(ACKNOWLEDGEMENT_TYPE_VALUE):
            print("CLIENT: Invalid Type Value")
            return False
        return initial_message[2] # Returns the Length from Ack Message
    except struct.error as e:
        print("CLIENT: Invalid Data Format - ", e)
        return False


def check_hash_response(encoded_data):
    """
    Checks the hash response message.

    Args:
        encoded_data (bytes): Encoded data to be checked.

    Returns:
        bool or tuple: False if invalid message, otherwise returns the struct object.
    """

    try:
        initial_message = open_struct(encoded_data)
        type_val = socket.ntohs(initial_message[0])
        if type_val != socket.ntohs(HASH_RESPONSE_TYPE_VALUE):
            print("CLIENT: Invalid Type Value")
            return False
        return initial_message # Returns Struct Object
    except struct.error as e:
        print("CLIENT: Invalid Data Format - ", e)
        return False


def connect_server(ip, port):
    """
    Create a socket and connect to server. Then,
    return the socket object.

    Args:
        ip (str): Server IP address.
        port (int): Server port number.

    Returns:
        socket.socket: Socket object for communication with the server.
    """
    
    tcp_socket = socket.socket()
    tcp_socket.connect((ip, port))

    print("Connected to server!")
    return tcp_socket


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    if len(sys.argv) < 9:
        print('Usage : "python client.py -a server_ip -p server_port -s hash_block_size -f file_path"\n[server_ip : ip address of the server]\n[server_port: port number of the server to connect]\n[hash_block_size: The size of each HashRequest Data Payload that the client will send to the server]\n[file_path: The file that the client reads data from for all HashRequests]')
        sys.exit(2)

    # Create dictionary with keys being the flags [-a, -p, -s, -f]
    args = {}
    for flag, value in zip(sys.argv[1::2], sys.argv[2::2]):
        args[flag] = value
    
    if '-a' not in args or '-p' not in args or '-s' not in args or '-f' not in args:
        print("Error: Missing required options.")
        sys.exit(2)

    # Variables we need from the command line
    server_ip = args['-a']  # Extract server IP
    server_port = int(args['-p'])  # Extract server port
    hash_block_size = int(args['-s'])  # Extract S
    file_path = args['-f']  # Extract file path

    if not os.path.exists(file_path):
        print("Error: Path does not exist.")
        sys.exit(2)

    # Open our file from command line
    chosen_file = open(file_path)
    blocks = chosen_file.readlines()

    # Connect to the server!
    server_socket = connect_server(server_ip, server_port)

    # Create initialization message and send to the server
    initialization_message = create_initialization(hash_block_size)
    if not initialization_message:
        sys.exit(2)
    server_socket.sendall(initialization_message)
    print("Initialization sent.")

    # Acknowledgement Message Verification
    length = check_acknowledgement(server_socket.recv(1024))  
    if not length:
        sys.exit(2)    

    # Let's keep track of hash count, and our new hashed data file
    # you can write the hash values received from the server in this file
    count = 0
    hashed_data = open("outfile-clientIP.txt", 'a')
    print("New Hashed File Created.")
    
    for block in blocks:
        request_message = create_hash_request(count, block)
        server_socket.sendall(request_message)
        print("Hash Request sent.")

        response_type, response_i, response_len, response_payload = check_hash_response(server_socket.recv(1024))
        try:
            print("Writing {} {} : {} {} to outfile-cllientIP.txt\n".format(block.strip(), count, response_payload, response_i))
            hashed_data.write("{} {}: {} {}\n".format(block.strip(), count, response_payload, response_i)) 
            hashed_data.flush()
        except IOError as e:
            print ("I/O error: ", e)
        count += 1
    
    # We're done - Let's close our open files and sockets
    print("Done! Closing files and sockets.")
    hashed_data.close()  # New Hash Data File
    chosen_file.close()  # Command Line File
    server_socket.close()  # Server Socket
