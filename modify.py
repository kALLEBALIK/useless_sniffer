import unpack
import pprint as pp



# Strip if none of attributes exists in packet
def packet_strip(pkts, dest_ip=[], dest_port=[], src_ip=[], src_port=[], proto=[]):

    def match(packet):
        filters = [
            dest_ip,
            dest_port,
            src_ip,
            src_port,
            proto]
    
        _tpls = [
            unpack.IP_DESTINATION_ADDRESS,
            unpack.TCP_DESTINATION_PORT,
            unpack.IP_SOURCE_ADDRESS,
            unpack.TCP_SOURCE_PORT,
            unpack.IP_PROTOCOL]

        for f in range(0, len(filters)):
            for i in range(0, len(filters[f])):
                if packet[_tpls[f]] == filters[f][i]:
                    return True
    
    return list(filter(match, pkts))



# Sort by tuple:
# -IP Protool
# -IP Source address
# -IP Destionation adress
# -TCP Source port
# -TCP Destination port
def sort_by_tuple(packets):
    grouped_packets = [[packets[0]]]
    for i in range(1, len(packets)):
        pushed = False
        for k in range(0, len(grouped_packets)):
            if contain_tuple(grouped_packets[k][0], packets[i]):
                grouped_packets[k].append(packets[i])
                pushed = True
                break
        if not pushed:
            grouped_packets.append([packets[i]])

    return grouped_packets



# compare
def contain_tuple(grouped, packet):
    return not(
        grouped[unpack.IP_PROTOCOL]            != packet[unpack.IP_PROTOCOL]            or
        grouped[unpack.IP_SOURCE_ADDRESS]      != packet[unpack.IP_SOURCE_ADDRESS]      or
        grouped[unpack.IP_DESTINATION_ADDRESS] != packet[unpack.IP_DESTINATION_ADDRESS] or
        grouped[unpack.TCP_SOURCE_PORT]        != packet[unpack.TCP_SOURCE_PORT]        or
        grouped[unpack.TCP_DESTINATION_PORT]   != packet[unpack.TCP_DESTINATION_PORT])



# Group payloads to single payload
def group_tuple_payload(tuple_sorted_packet):
    grouped_payload_tuple = []
    for g in range(0, len(tuple_sorted_packet)):
        if len(tuple_sorted_packet[g]) > 1:
            for i in range(0, len(tuple_sorted_packet[g])):
                if i == 0:
                    grouped_payload_tuple.append({
                            unpack.IP_PROTOCOL:            tuple_sorted_packet[g][i][unpack.IP_PROTOCOL],
                            unpack.IP_SOURCE_ADDRESS:      tuple_sorted_packet[g][i][unpack.IP_SOURCE_ADDRESS],
                            unpack.IP_DESTINATION_ADDRESS: tuple_sorted_packet[g][i][unpack.IP_DESTINATION_ADDRESS],
                            unpack.TCP_SOURCE_PORT:        tuple_sorted_packet[g][i][unpack.TCP_SOURCE_PORT],
                            unpack.TCP_DESTINATION_PORT:   tuple_sorted_packet[g][i][unpack.TCP_DESTINATION_PORT],
                            unpack.TCP_PAYLOAD_DATA:      [tuple_sorted_packet[g][i][unpack.TCP_PAYLOAD_DATA]]})
                else:
                    grouped_payload_tuple[g][unpack.TCP_PAYLOAD_DATA].append(
                        tuple_sorted_packet[g][i][unpack.TCP_PAYLOAD_DATA])
        else:
            grouped_payload_tuple.append({
                unpack.IP_PROTOCOL:            tuple_sorted_packet[g][0][unpack.IP_PROTOCOL],
                unpack.IP_SOURCE_ADDRESS:      tuple_sorted_packet[g][0][unpack.IP_SOURCE_ADDRESS],
                unpack.IP_DESTINATION_ADDRESS: tuple_sorted_packet[g][0][unpack.IP_DESTINATION_ADDRESS],
                unpack.TCP_SOURCE_PORT:        tuple_sorted_packet[g][0][unpack.TCP_SOURCE_PORT],
                unpack.TCP_DESTINATION_PORT:   tuple_sorted_packet[g][0][unpack.TCP_DESTINATION_PORT],
                unpack.TCP_PAYLOAD_DATA:      [tuple_sorted_packet[g][0][unpack.TCP_PAYLOAD_DATA]]})
    
    return grouped_payload_tuple
