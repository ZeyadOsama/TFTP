# Don't forget to change this file's name before submission.
import enum
import os
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

    class TftpPacketType(enum.Enum):
        """
        Represents a TFTP packet type add the missing types here and
        modify the existing values as necessary.
        """
        RRQ, WRQ, DATA, ACK, ERROR = range(1, 6)

    class Constants:

        class Types(str):
            RRQ = 'RRQ'
            WRQ = 'WRQ'
            ACK = 'ACK'
            DATA = 'DATA'
            ERROR = 'ERR'

        class Opcodes(int):
            """
            Represents a TFTP packet type add the missing types here and
            modify the existing values as necessary.
            """
            RRQ, WRQ, DATA, ACK, ERROR = range(1, 6)

        MODE = 'octet'

        FORMATS = {Types.RRQ: '!H{}sx{}sx',
                   Types.WRQ: '!H{}sx{}sx',
                   Types.ACK: '!HH',
                   Types.DATA: '!HH{}s',
                   Types.ERROR: '!HH{}sx'}

    def __init__(self):
        """
        Add and initialize the *internal* fields you need.
        Do NOT change the arguments passed to this function.

        Here's an example of what you can do inside this function.
        """
        self.packet_buffer = []

    def process_udp_packet(self, packet_data, packet_source):
        """
        Parse the input packet, execute your logic according to that packet.
        packet data is a bytearray, packet source contains the address
        information of the sender.
        """
        # Add your logic here, after your logic is done,
        # add the packet to be sent to self.packet_buffer
        # feel free to remove this line
        print(f"Received a packet from {packet_source}")
        in_packet = self._unpack_udp_packet(packet_data)
        out_packet = self._pack_udp_packet(in_packet)

        # This shouldn't change.
        self.packet_buffer.append(out_packet)

    def _unpack_udp_packet(self, packet_bytes):
        """
        You'll use the struct module here to determine
        the type of the packet and extract other available
        information.
        """
        return {
            self.Constants.Opcodes.DATA: self._unpack_DATA(packet_bytes),
            self.Constants.Opcodes.ACK: self._unpack_ACK(packet_bytes),
            self.Constants.Opcodes.ERROR: self._unpack_ERROR(packet_bytes)
        }.get(int.from_bytes(packet_bytes[:2], byteorder='big'), '[ERROR] No such opcode.')

    def _unpack_DATA(self, packet_bytes):
        pass

    def _unpack_ACK(self, packet_bytes):
        pass

    def _unpack_ERROR(self, packet_bytes):
        pass

    def _pack_udp_packet(self, input_packet):
        """
        Example of a private function that does some logic.
        """
        return {
            self.Constants.Opcodes.DATA: self._pack_DATA(input_packet),
            self.Constants.Opcodes.ACK: self._pack_ACK(input_packet),
            self.Constants.Opcodes.ERROR: self._pack_ERROR(input_packet)
        }.get(int.from_bytes(input_packet[0], byteorder='big'), '[ERROR] No such opcode.')

    def _pack_DATA(self, input_packet):
        pass

    def _pack_ACK(self, input_packet):
        pass

    def _pack_ERROR(self, input_packet):
        pass

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

    def request_file(self, file_path_on_server):
        """
        This method is only valid if you're implementing
        a TFTP client, since the client requests or uploads
        a file to/from a server, one of the inputs the client
        accept is the file name. Remove this function if you're
        implementing a server.
        """
        values = (self.Constants.Types.RRQ, file_path_on_server, 0, self.Constants.MODE, 0)
        s = struct.Struct(
            self.Constants.FORMATS[self.Constants.Types.RRQ].format(
                len(file_path_on_server),
                len(self.Constants.MODE)))
        return s.pack(*values)

    def upload_file(self, file_path_on_server):
        """
        This method is only valid if you're implementing
        a TFTP client, since the client requests or uploads
        a file to/from a server, one of the inputs the client
        accept is the file name. Remove this function if you're
        implementing a server.
        """
        try:
            open(file_path_on_server, "rb")
        except IOError:
            print("File not found.")
            return None


def check_file_name():
    """
    Checks script's name for lab purposes.
    """
    script_name = os.path.basename(__file__)
    import re
    matches = re.findall(r"(\d{4}_)+lab1\.(py|rar|zip)", script_name)
    if not matches:
        print(f"[WARN] File name is invalid [{script_name}]")
    pass


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


def do_socket_logic():
    """
    Example function for some helper logic, in case you
    want to be tidy and avoid stuffing the main function.

    Feel free to delete this function.
    """
    pass


def parse_user_input(address, operation, file_name=None):
    # Your socket logic can go here,
    # you can surely add new functions
    # to contain the socket code.
    # But don't add socket code in the TftpProcessor class.
    # Feel free to delete this code as long as the
    # functionality is preserved.
    if operation == "push":
        print(f"Attempting to upload [{file_name}]...")
        pass
    elif operation == "pull":
        print(f"Attempting to download [{file_name}]...")
        pass


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
            print(
                f"[FATAL] The command-line argument #[{param_index}] is missing")
            exit(-1)  # Program execution failed.


def main():
    """
     Write your code above this function.
    if you need the command line arguments
    """
    print("*" * 50)
    print("[LOG] Printing command line arguments\n", ",".join(sys.argv))
    check_file_name()
    print("*" * 50)

    # This argument is required.
    # For a server, this means the IP that the server socket
    # will use.
    # The IP of the server, some default values
    # are provided. Feel free to modify them.
    ip_address = get_arg(1, "127.0.0.1")
    operation = get_arg(2, "pull")
    file_name = get_arg(3, "test.txt")

    # Modify this as needed.
    parse_user_input(ip_address, operation, file_name)


if __name__ == "__main__":
    main()
