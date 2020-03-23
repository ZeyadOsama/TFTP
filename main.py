# Don't forget to change this file's name before submission.
import socket
import struct
import sys


class TftpProcessor(object):
    """
    Implements logic for a TFTP client.
    The input to this object is a received UDP packet,
    the output is the packets to be written to the socket.

    This class MUST NOT know anything about the existing sockets
    its input and outputs are byte arrays ONLY.

    Store the output packets in a buffer (some list) in this class
    the function get_next_output_packet returns the first item in
    the packets to be sent.

    This class is also responsible for reading/writing files to the
    hard disk.

    Failing to comply with those requirements will invalidate
    your submission.

    Feel free to add more functions to this class as long as
    those functions don't interact with sockets nor inputs from
    user/sockets. For example, you can add functions that you
    think they are "private" only. Private functions in Python
    start with an "_", check the example below
    """

    class Constants:

        class Types(int):
            DATA, ACK, ERROR = range(3, 6)

        class Requests(int):
            RRQ, WRQ = range(1, 3)

        class Lengths(int):
            ACK = 4
            DATA = 4
            ERROR = 5

        MAX_READ_BYTES = 1024
        READ_BYTES = 512
        MODE = 'octet'

        BLOCK_INDEX = 1

        FORMATS = {Requests.RRQ: '!H{}sx{}sx',
                   Requests.WRQ: '!H{}sx{}sx',
                   Types.ACK: '!HH',
                   Types.DATA: '!HH{}s',
                   Types.ERROR: '!HH{}sx'}

    def __init__(self):
        """
        Add and initialize the internal fields you need.
        Do NOT change the arguments passed to this function.

        Here's an example of what you can do inside this function.
        """
        self.packet_buffer = []
        self.data_buffer = []
        self.file = None
        self.check_mark: bool = False

    def process_udp_packet(self, packet_data, packet_source):
        """
        Parse the input packet, execute your logic according to that packet.
        packet data is a bytearray, packet source contains the address
        information of the sender.
        """
        # Add your logic here, after your logic is done,
        # add the packet to be sent to self.packet_buffer
        # feel free to remove this line
        print(f'\nReceived packet from {packet_source}.')
        in_packet = self._unpack_udp_packet(packet_data)
        out_packet = self._pack_udp_packet(in_packet)
        if type(out_packet) == str:
            print(out_packet)
            return
        if out_packet is None:
            print(f'\nData upload to {packet_source} complete.')
            self.file.close()
            return
        # This shouldn't change.
        self.packet_buffer.append(out_packet)

    def _unpack_udp_packet(self, packet_data):
        """
        You'll use the struct module here to determine
        the type of the packet and extract other available
        information.
        """
        opcode = int.from_bytes(packet_data[:2], byteorder='big')
        if opcode == self.Constants.Types.DATA:
            return self._unpack_DATA(packet_data)
        elif opcode == self.Constants.Types.ACK:
            return self._unpack_ACK(packet_data)
        elif opcode == self.Constants.Types.ERROR:
            return self._unpack_ERROR(packet_data)

    def _unpack_DATA(self, packet_data):
        s = struct.unpack(
            self.Constants.FORMATS[self.Constants.Types.DATA].format(len(packet_data) - self.Constants.Lengths.DATA),
            packet_data)
        print(f'[UNPACK][DATA] Block: {s[self.Constants.BLOCK_INDEX]}')
        return s

    def _unpack_ACK(self, packet_data):
        s = struct.unpack(self.Constants.FORMATS[self.Constants.Types.ACK], packet_data)
        print(f'[UNPACK][ACK] Block: {s[self.Constants.BLOCK_INDEX]}')
        return s

    def _unpack_ERROR(self, packet_data):
        s = struct.unpack(
            self.Constants.FORMATS[self.Constants.Types.ERROR].format(len(packet_data) - self.Constants.Lengths.ERROR),
            packet_data)
        print(f'[UNPACK][ERROR] Block: {s[self.Constants.BLOCK_INDEX]}')
        return s

    def _pack_udp_packet(self, input_packet):
        """
        Example of a private function that does some logic.
        """
        opcode = input_packet[0]
        if opcode == 3:
            return self._pack_ACK(input_packet)
        elif opcode == 4:
            return self._pack_DATA(input_packet)
        elif opcode == 5:
            return self._pack_ERROR(input_packet)

    def _pack_DATA(self, input_packet):
        block_num = input_packet[-1] + 1
        print(f'[PACK][DATA] Block: {input_packet[self.Constants.BLOCK_INDEX]}')
        if input_packet[-1] == len(self.data_buffer):
            self.check_mark = True
        if self.has_pending_data():
            data = self.get_next_data()
            values = (self.Constants.Types.DATA, block_num, data)
            s = struct.Struct(
                self.Constants.FORMATS[self.Constants.Types.DATA].format(
                    len(data)))
            return s.pack(*values)

    def _pack_ACK(self, input_packet):
        block_num = input_packet[1]
        print(f'[PACK][ACK] Block: {input_packet[self.Constants.BLOCK_INDEX]}')
        if len(input_packet[2]) != self.Constants.READ_BYTES:
            self.check_mark = True
        self._writeFile(input_packet[2])
        values = (self.Constants.Types.ACK, block_num)
        s = struct.Struct(self.Constants.FORMATS[self.Constants.Types.ACK])
        return s.pack(*values)

    def _pack_ERROR(self, input_packet):
        print(f'[PACK][ERROR] Block: {input_packet[self.Constants.BLOCK_INDEX]}')
        return input_packet[2].decode('ascii')

    def _packetize_file(self):
        ba_file = bytearray(self.file.read())
        for i in range(0, len(ba_file), self.Constants.READ_BYTES):
            if i + self.Constants.READ_BYTES > len(ba_file):
                data = ba_file[i:]
            else:
                data = ba_file[i:i + self.Constants.READ_BYTES]
            self.data_buffer.append(data)
        print(f'[LOG] Packetize done.')

    def get_next_data(self):
        return self.data_buffer.pop(0)

    def has_pending_data(self):
        return len(self.data_buffer) != 0

    def get_next_output_packet(self):
        """
        Returns the next packet that needs to be sent.
        This function returns a byetarray representing
        the next packet to be sent.

        For example;
        s_socket.send(tftp_processor.get_next_output_packet())

        Leave this function as is.
        """
        return self.packet_buffer.pop(0)

    def has_pending_packets_to_be_sent(self):
        """
        Returns if any packets to be sent are available.

        Leave this function as is.
        """
        return len(self.packet_buffer) != 0

    def _writeFile(self, data):
        self.file.write(data)

    def request_file(self, file_path_on_server):
        """
        This method is only valid if you're implementing
        a TFTP client, since the client requests or uploads
        a file to/from a server, one of the inputs the client
        accept is the file name. Remove this function if you're
        implementing a server.
        """
        return self._file_request(self.Constants.Requests.RRQ, file_path_on_server)

    def upload_file(self, file_path_on_server):
        """
        This method is only valid if you're implementing
        a TFTP client, since the client requests or uploads
        a file to/from a server, one of the inputs the client
        accept is the file name. Remove this function if you're
        implementing a server.
        """
        return self._file_request(self.Constants.Requests.WRQ, file_path_on_server)

    def _file_request(self, request: Constants.Requests, file_path_on_server):
        if request == self.Constants.Requests.RRQ:
            self.file = open(file_path_on_server, 'wb')
        else:
            try:
                self.file = open(file_path_on_server, 'rb')
            except IOError:
                print(f'[ERROR] File not found.')
                exit(-1)
            self._packetize_file()
        return self._pack_request(request, file_path_on_server)

    def _pack_request(self, request, file_path_on_server):
        values = (request, file_path_on_server.encode('ascii'), self.Constants.MODE.encode('ascii'))
        s = struct.Struct(
            self.Constants.FORMATS[request].format(
                len(file_path_on_server),
                len(self.Constants.MODE)))
        return s.pack(*values)


def default_port():
    """
    :return: tftp and udp default port number for initiating the communication process.
    """
    return socket.getservbyname('tftp', 'udp')


def setup_sockets(address):
    """
    Socket logic MUST NOT be written in the TftpProcessor
    class. It knows nothing about the sockets.

    :return client's socket, server address (IP address, port number)
    """
    return socket.socket(socket.AF_INET, socket.SOCK_DGRAM), (address, default_port())


def start(processor, client):
    while True:
        data, source = client.recvfrom(TftpProcessor.Constants.MAX_READ_BYTES)
        processor.process_udp_packet(data, source)
        if processor.has_pending_packets_to_be_sent():
            client.sendto(processor.get_next_output_packet(), source)
            if processor.check_mark:
                break
        else:
            break


def start_RRQ(processor, file_name):
    print(f'Attempting to download [{file_name}]...')
    return processor.request_file(file_name)


def start_WRQ(processor, file_name):
    print(f'Attempting to upload [{file_name}]...')
    WRQ = processor.upload_file(file_name)
    if WRQ is None:
        print(f'[ERROR] {file_name} does not exist.')
        exit(-1)
    return WRQ


def parse_user_input(address, operation, file_name=None):
    # Your socket logic can go here,
    # you can surely add new functions
    # to contain the socket code.
    # But don't add socket code in the TftpProcessor class.
    # Feel free to delete this code as long as the
    # functionality is preserved.
    client_socket, server_address = setup_sockets(address)

    processor = TftpProcessor()
    request = None

    if operation == 'push':
        request = start_WRQ(processor, file_name)
    elif operation == 'pull':
        request = start_RRQ(processor, file_name)
    else:
        print(f'[ERROR] {operation} does not exist.')
        exit(-1)

    client_socket.sendto(request, server_address)
    start(processor, client_socket)


def get_arg(param_index, default=None):
    """
    Gets a command line argument by index (note: index starts from 1)
    If the argument is not supplies, it tries to use a default value.
    If a default value isn't supplied, an error message is printed
    and terminates the program.
    """
    try:
        return sys.argv[param_index]
    except IndexError as e:
        if default:
            return default
        else:
            print(e)
            print(f"[FATAL] The command-line argument #[{param_index}] is missing")
            exit(-1)


def main():
    """
     Write your code above this function.
    if you need the command line arguments
    """
    print("*" * 50)
    print("[LOG] Printing command line arguments\n", ",".join(sys.argv))
    print("*" * 50)

    # This argument is required.
    # For a server, this means the IP that the server socket
    # will use.
    # The IP of the server, some default values
    # are provided. Feel free to modify them.
    ip_address = get_arg(1, "127.0.0.1")
    operation = get_arg(2, "push")
    file_name = get_arg(3, "hello.txt")

    # Modify this as needed.
    parse_user_input(ip_address, operation, file_name)


if __name__ == "__main__":
    main()
