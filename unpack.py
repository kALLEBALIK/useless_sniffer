import struct
from socket import inet_ntoa


#TCP FRAGMENT
TCP_SOURCE_PORT = 'TCP_SOURCE_PORT'
TCP_DESTINATION_PORT ='TCP_DESTINATION_PORT'
TCP_SEQUENCE_NUMBER = 'TCP_SEQUENCE_NUMBER'
TCP_ACKNOWLEDGEMENT_NUMBER = 'TCP_ACKNOWLEDGEMENT_NUMBER'
TCP_OFFSET = 'TCP_OFFSET'
TCP_RESERVED = 'TCP_RESERVED'
TCP_FLAGS = 'TCP_FLAGS'
TCP_WINDOW = 'TCP_WINDOW'
TCP_CHECKSUM = 'TCP_CHECKSUM'
TCP_POINTER = 'TCP_POINTER'
TCP_PAYLOAD_DATA = 'TCP_PAYLOAD_DATA'

#TCP flags
TCP_FLAG_CWR = 'TCP_FLAG_CWR'
TCP_FLAG_ECE = 'TCP_FLAG_ECE'
TCP_FLAG_URG = 'TCP_FLAG_URG'
TCP_FLAG_ACK = 'TCP_FLAG_ACK'
TCP_FLAG_PSH = 'TCP_FLAG_PSH'
TCP_FLAG_RST = 'TCP_FLAG_RST'
TCP_FLAG_SYN = 'TCP_FLAG_SYN'
TCP_FLAG_FIN = 'TCP_FLAG_FIN'

#IP HEADER
IP_VERSION = 'IP_VERSION'
IP_IHL = 'IP_IHL'
IP_TOS = 'IP_TOS'
IP_TOTAL_LENGTH = 'IP_TOTAL_LENGTH'
IP_ID = 'IP_ID'
IP_FLAGS = 'IP_FLAGS'
IP_FRAGMENT_OFFSET = 'IP_FRAGMENT_OFFSET'
IP_TTL = 'IP_TTL'
IP_PROTOCOL = 'IP_PROTOCOL'
IP_HEADER_CHECKSUM = 'IP_HEADER_CHECKSUM'
IP_SOURCE_ADDRESS = 'IP_SOURCE_ADDRESS'
IP_DESTINATION_ADDRESS =  'IP_DESTINATION_ADDRESS'

#IP flag
IP_FLAG_RF = 'IP_FLAG_RF'
IP_FLAG_DF = 'IP_FLAG_DF'
IP_FLAG_MF = 'IP_FLAG_MF'

# IP TOS flags
IP_TOS_PRECEDENSE = 'IP_TOS_PRECEDENS'
IP_TOS_DELAY = 'IP_TOS_DELAY'
IP_TOS_THROUGHPUT = 'IP_TOS_THROUGHPUT'
IP_TOS_RELIABILITY = 'IP_TOS_RELIABILITY'
IP_TOS_MONETARY = 'IP_TOS_MONETARY'
IP_TOS_RESERVED = 'IP_TOS_RESERVED'



# Unpack tcp fragment
def tcp_fragment(tcp_data):
    tcp_header = struct.unpack('! HHLLBBHHH', tcp_data[:20])
    source_port = tcp_header[0]
    destionation_port = tcp_header[1]
    sequence_number = tcp_header[2]
    acknowledgement_number = tcp_header[3]
    offset = tcp_header[4] >> 4
    reserved = tcp_header[4] & 0xF
    flags = get_tcp_flags(tcp_header[5])
    window = tcp_header[6]
    checksum = tcp_header[7]
    pointer = tcp_header[8]

    return {
        TCP_SOURCE_PORT: source_port,
        TCP_DESTINATION_PORT: destionation_port,
        TCP_SEQUENCE_NUMBER: sequence_number,
        TCP_ACKNOWLEDGEMENT_NUMBER: acknowledgement_number,
        TCP_OFFSET: offset,
        TCP_RESERVED: reserved,
        TCP_FLAGS: flags,
        TCP_WINDOW: window,
        TCP_CHECKSUM: checksum,
        TCP_POINTER: pointer,
        TCP_PAYLOAD_DATA: tcp_data[20:]
    }



# Get flags in tcp header
def get_tcp_flags(flags):
    C = flags >> 7
    E = flags & 0x40
    E >>= 6
    U = flags & 0x20
    U >>= 5
    A = flags & 0x10
    A >>= 4
    P = flags & 0x8
    P >>= 3
    R = flags & 0x4
    R >>= 2
    S = flags & 0x2
    S >>= 1
    F = flags & 0x1

    return {
        TCP_FLAG_CWR: C,
        TCP_FLAG_ECE: E,
        TCP_FLAG_URG: U,
        TCP_FLAG_ACK: A,
        TCP_FLAG_PSH: P,
        TCP_FLAG_RST: R,
        TCP_FLAG_SYN: S,
        TCP_FLAG_FIN: F,
    }



# Unpack ip header
def ip_header(raw_data):
    ip_header = struct.unpack('! BBHHHBBH4s4s', raw_data[:20])
    version = ip_header[0] >> 4
    IHL = ip_header[0] & 0xF
    TOS = get_tos(ip_header[1])
    total_length = ip_header[2]
    ID = ip_header[3]
    flags = get_ip_header_flags(ip_header[4])
    fragment_offset = ip_header[4] & 0x1FFF
    TTL = ip_header[5]
    protocol = ip_header[6]
    header_checksum = ip_header[7]
    source_address = inet_ntoa(ip_header[8])
    destination_address = inet_ntoa(ip_header[9])

    return {
        IP_VERSION: version,
        IP_IHL: IHL,
        IP_TOS: TOS,
        IP_TOTAL_LENGTH: total_length,
        IP_ID: ID,
        IP_FLAGS: flags,
        IP_FRAGMENT_OFFSET: fragment_offset,
        IP_TTL: TTL,
        IP_PROTOCOL: protocol,
        IP_HEADER_CHECKSUM: header_checksum,
        IP_SOURCE_ADDRESS: source_address,
        IP_DESTINATION_ADDRESS: destination_address
    }



# Unpack ip header flags
def get_ip_header_flags(fragment):
    RF = fragment >> 15
    DF = fragment & 0x4000
    DF >>= 14
    MF = fragment & 0x2000
    MF >>= 13

    return {
        IP_FLAG_RF: RF,
        IP_FLAG_DF: DF,
        IP_FLAG_MF: MF
    }



# Unpack tos
def get_tos(TOS):
    P = TOS >> 5
    D = TOS & 0x10
    D >>= 4
    T = TOS & 0x8
    T >>= 3
    R = TOS & 0x4
    R >>= 2
    M = TOS & 0x2
    M >>= 1
    RES = TOS & 0x1

    return {
        IP_TOS_PRECEDENSE: P,
        IP_TOS_DELAY: D,
        IP_TOS_THROUGHPUT: T,
        IP_TOS_RELIABILITY: R,
        IP_TOS_MONETARY: M,
        IP_TOS_RESERVED: RES
    }
