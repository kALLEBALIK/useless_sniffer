import socket
import struct
import binascii
import pprint as pp
import network
import time
import uuid
import stringify
import unpack
import time
import modify



def main(write_file=False):
    # Timing
    run_sniffer_for = int(input('For how many second should sniffer run?: ')) * 1000
    run_start = int(round(time.time() * 1000))

    # Init network socket
    local_ip = socket.gethostbyname(socket.gethostname())
    net = network.Network(local_ip, 0)

    # f
    if write_file:
        f = create_write_file()

    all_packets = []

    while True:
        # Get data
        try:
            raw_data = net.get_raw_data()
        except OSError:
            print('Could not get packet!')
            continue

        # Unpack data
        unpacked_ip_header = unpack.ip_header(raw_data)
        unpacked_tcp_header = unpack.tcp_fragment(raw_data)
        # Merge unpacked data to one dict
        merged_tcp_ip = {**unpacked_ip_header, **unpacked_tcp_header}
        # Move to paccket
        all_packets.append(merged_tcp_ip)

        # Create readable Format data
        readable_result = stringify.tcp_ip(unpacked_ip_header, unpacked_tcp_header, stringify.MODE_HEX_PAIR)

        # f
        if write_file:
            f.write(readable_result + "\n\n")
        
        # Timing
        elapsed_time = int(round(time.time() * 1000))
        print((elapsed_time - run_start) / 1000)
        if elapsed_time - run_start > run_sniffer_for:
            break

        #print(readable_result)

    sorted_packets = modify.sort_by_tuple(all_packets)
    grouped_payload = modify.group_tuple_payload(sorted_packets)
    print(stringify.grouped_tuple_payload(grouped_payload))
    pp.pprint(modify.packet_strip(all_packets, [], [40]))

    net.close()

     # f
    if write_file:
        f.close()



# Create txt file with random name and timestamp
def create_write_file():
    return open(generate_filename(), 'w')



# Generate name
def generate_filename():
    timestamp = time.strftime('D%y-%m-%d_T%H-%M-%S')
    filename = ('{}_{}.txt').format(timestamp, str(uuid.uuid4()))
    return filename



# Get encodings from list supported by python
def get_standard_encodings():
    f = open('standard_encodings.txt', 'r')
    encodings =  map(lambda line: line.split('\t')[0], f)
    f.close

    return encodings



main()
