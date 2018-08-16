import binascii
import unpack
import ustrings
import pprint as pp
import textwrap
import re



TAB_1 = '\n\t'
TAB_2 = '\n\t\t'
TAB_3 = '\n\t\t\t'
TAB_4 = '\n\t\t\t\t'

TAB_1_DATA = '\n\t- '
TAB_2_DATA = '\n\t\t- '
TAB_3_DATA = '\n\t\t\t- '
TAB_4_DATA = '\n\t\t\t\t- '

MODE_NONE = 0
MODE_HEX_PAIR = 1
MODE_HEX = 2
MODE_BYTES = 3
MODE_READABLE = 4
MODE_READABLE_STRIP = 5


# Create string with formated ip header
def tcp_header(unpacked_fragment):
    string  = TAB_1 + 'TCP HEADER \n'
    string += TAB_2 + 'Source port: '            + str(unpacked_fragment[unpack.TCP_SOURCE_PORT])
    string += TAB_2 + 'Destination port: '       + str(unpacked_fragment[unpack.TCP_DESTINATION_PORT])
    string += TAB_2 + 'Sequence number: '        + str(unpacked_fragment[unpack.TCP_SEQUENCE_NUMBER])
    string += TAB_2 + 'Acknowledgement number: ' + str(unpacked_fragment[unpack.TCP_ACKNOWLEDGEMENT_NUMBER])
    string += TAB_2 + 'Offset: '                 + str(unpacked_fragment[unpack.TCP_OFFSET])
    string += TAB_2 + 'Reserverd: '              + str(unpacked_fragment[unpack.TCP_RESERVED])
    string += TAB_2 + 'TCP Flags >'
    string += TAB_3_DATA + 'CWR: '               + str(unpacked_fragment[unpack.TCP_FLAGS][unpack.TCP_FLAG_CWR])
    string += TAB_3_DATA + 'ECE: '               + str(unpacked_fragment[unpack.TCP_FLAGS][unpack.TCP_FLAG_ECE])
    string += TAB_3_DATA + 'URG: '               + str(unpacked_fragment[unpack.TCP_FLAGS][unpack.TCP_FLAG_URG])
    string += TAB_3_DATA + 'ACK: '               + str(unpacked_fragment[unpack.TCP_FLAGS][unpack.TCP_FLAG_ACK])
    string += TAB_3_DATA + 'PSH: '               + str(unpacked_fragment[unpack.TCP_FLAGS][unpack.TCP_FLAG_PSH])
    string += TAB_3_DATA + 'RST: '               + str(unpacked_fragment[unpack.TCP_FLAGS][unpack.TCP_FLAG_RST])
    string += TAB_3_DATA + 'SYN: '               + str(unpacked_fragment[unpack.TCP_FLAGS][unpack.TCP_FLAG_SYN])
    string += TAB_3_DATA + 'FIN: '               + str(unpacked_fragment[unpack.TCP_FLAGS][unpack.TCP_FLAG_FIN])
    string += TAB_2 + 'Window: '                 + str(unpacked_fragment[unpack.TCP_WINDOW])
    string += TAB_2 + 'Checksum: '               + str(unpacked_fragment[unpack.TCP_CHECKSUM])
    string += TAB_2 + 'Pointer: '                + str(unpacked_fragment[unpack.TCP_POINTER])

    return string



# Create string with formated ip header
def ip_header(unpacked_header):
    string  = TAB_1 + 'IP HEADER'
    string += TAB_2 + 'Version: '              + str(unpacked_header[unpack.IP_VERSION])
    string += TAB_2 + 'IHL: '                  + str(unpacked_header[unpack.IP_IHL])
    string += TAB_2 + 'TOS >'
    string += TAB_3_DATA + 'Delay: '           + str(unpacked_header[unpack.IP_TOS][unpack.IP_TOS_DELAY])
    string += TAB_3_DATA + 'Monetary: '        + str(unpacked_header[unpack.IP_TOS][unpack.IP_TOS_MONETARY])
    string += TAB_3_DATA + 'Precedence: '      + str(unpacked_header[unpack.IP_TOS][unpack.IP_TOS_PRECEDENSE])
    string += TAB_3_DATA + 'reliability: '     + str(unpacked_header[unpack.IP_TOS][unpack.IP_TOS_RELIABILITY])
    string += TAB_3_DATA + 'Throughput: '      + str(unpacked_header[unpack.IP_TOS][unpack.IP_TOS_THROUGHPUT])
    string += TAB_2 + 'Total length: '         + str(unpacked_header[unpack.IP_TOTAL_LENGTH])
    string += TAB_2 + 'Identification: '       + str(unpacked_header[unpack.IP_ID])
    string += TAB_2 + 'Flags >'
    string += TAB_3_DATA + 'DF: '              + str(unpacked_header[unpack.IP_FLAGS][unpack.IP_FLAG_DF])
    string += TAB_3_DATA + 'MF: '              + str(unpacked_header[unpack.IP_FLAGS][unpack.IP_FLAG_MF])
    string += TAB_3_DATA + 'RF: '              + str(unpacked_header[unpack.IP_FLAGS][unpack.IP_FLAG_RF])
    string += TAB_2 + 'Fragment offset:'       + str(unpacked_header[unpack.IP_FRAGMENT_OFFSET])
    string += TAB_2 + 'TTL: '                  + str(unpacked_header[unpack.IP_TTL])
    string += TAB_2 + 'Protocol: '             + str(unpacked_header[unpack.IP_PROTOCOL])
    string += TAB_2 + 'Header checksum: '      + str(unpacked_header[unpack.IP_HEADER_CHECKSUM])
    string += TAB_2 + 'Source address: '       + unpacked_header[unpack.IP_SOURCE_ADDRESS]
    string += TAB_2 + 'Destionation address: ' + unpacked_header[unpack.IP_DESTINATION_ADDRESS]

    return string



def grouped_tuple_payload(gpl, mode):
    string = ''
    for i in range(0, len(gpl)):
        string += TAB_1 + 'GROUPED TUPLE PAYLOAD: {}'.format(str(i))
        string += TAB_2 + 'Source address: '     + str(gpl[i][unpack.IP_SOURCE_ADDRESS])
        string += TAB_2 + 'Source port: '        + str(gpl[i][unpack.TCP_SOURCE_PORT])
        string += TAB_2 + 'Destination address: '+ str(gpl[i][unpack.IP_DESTINATION_ADDRESS])
        string += TAB_2 + 'Destination port: '   + str(gpl[i][unpack.TCP_DESTINATION_PORT])
        string += TAB_2 + 'Payload ({}) > \n'.format(str(len(gpl[i][unpack.TCP_PAYLOAD_DATA])))

        for payload_packet in gpl[i][unpack.TCP_PAYLOAD_DATA]:
            string += hex_dump(payload_packet, mode)

    return string



# Create string with formated ip header and tcp header
def tcp_ip(unpacked_ip_header, unpacked_tcp_fragment, debug_mode = MODE_NONE):
    string  = ip_header(unpacked_ip_header)
    string += tcp_header(unpacked_tcp_fragment)
    string += TAB_1 + 'Debug Payload > \n\n'
    string += hex_dump(unpacked_tcp_fragment[unpack.TCP_PAYLOAD_DATA], debug_mode)
    string += ustrings.DASH_SEPARATOR

    return string



# Format hex dump
def hex_dump(_bytes , mode = MODE_HEX_PAIR):
    _hex = binascii.hexlify(_bytes)
    bit_pair = [_hex[i:i+2] for i in range(0, len(_hex), 2)]

    string = ''

    if mode == MODE_HEX_PAIR:
        for pair in bit_pair:
            string += pair.decode('utf-8').upper() + '  '
    elif mode == MODE_HEX:
        string += _hex.decode('utf-8')
    elif mode == MODE_BYTES:
        string += format_multi_line('', _bytes)
    elif mode == MODE_READABLE:
        string += _bytes.decode('ascii', 'replace')
        return string.replace('�', '.').strip() 
    elif mode == MODE_READABLE_STRIP:
        string += _bytes.decode('ascii', 'replace')
        regex = re.compile('[^a-zA-Z0-9\.\-_:/]')
        string = regex.sub('', string)
    else:
        return string
        
    return(format_multi_line('', string))


# format multi-line string
def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line  in textwrap.wrap(string, size)])