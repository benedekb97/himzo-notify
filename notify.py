import pyshark
import constant


# parse control word
def process_data(data, c_stitches=None):

    if c_stitches is not None:
        print("Running")

    # check if machine is running
    if data[7] == constant.STATE_RUNNING_FIRST and data[8] == constant.STATE_RUNNING_SECOND:
        print("Running")
    elif data[7] == constant.STATE_END_FIRST and data[8] == constant.STATE_END_SECOND:
        print("End")
    elif data[7] == constant.STATE_OTHER_FIRST:
        if data[8] == constant.STATE_MACHINE_ERROR_SECOND:
            print("Machine error")
        elif data[8] == constant.STATE_END_MANUAL_SECOND:
            print("End")
        elif data[8] == constant.STATE_STOP_SECOND:
            print("Stop switch")
        elif data[8] == constant.STATE_NEEDLE_STOP_SECOND:
            print("Needle stop")
        elif data[8] == constant.STATE_THREAD_BREAK_SECOND:
            print("Thread break")


# check incoming data if its a dst file
def check_for_dst(data):
    return data[len(data)-7] == "54" and data[len(data)-8] == "53" and data[len(data)-9] == "44" and data[8] == "48"


# check whether incoming data is the end of the packet
def check_for_end_of_packet(data):
    return data[len(data)-1] == "00" and data[len(data)-2] == "0d" and data[len(data)-3] == "03"


# check whether incoming data is the start of a packet
def check_for_start(data):
    for i in range(2, len(data)-1):
        if data[i] == "83" and data[i-1] == "00" and data[i-2] == "00":
            return i


# start capture loop
cap = pyshark.LiveCapture(None, bpf_filter='tcp port 7891')
img_data = []
dst_data = []
image_set = False
dst_incoming = False
first_packet = False
for packet in cap.sniff_continuously():
    if packet[1].src == constant.IP_PC and hasattr(packet.tcp, 'payload'):
        payload = packet.tcp.payload.split(':')
        if dst_incoming:
            if first_packet:
                payload = payload[12:]
                first_packet = False
            if check_for_end_of_packet(payload):
                payload = payload[:len(payload)-3]
            for i in range(0, len(payload)):
                if i+2 < len(payload)-1 and payload[i] == "00" and payload[i+1] == "00" and payload[i+2] == "f3":
                    dst_data.append("0000f31a")
                    dst_incoming = False
                    first_packet = False
                    break
                dst_data.append(payload[i])

    if packet[1].src == constant.IP_MACHINE and hasattr(packet.tcp, 'payload'):
        payload = packet.tcp.payload.split(':')
        payload_dec = []
        for hex_number in payload:
            payload_dec.append(int(hex_number, 16))

        if len(payload) == 21:
            designs = int(payload[10])
            current_design = int(payload[12])+1

            print("Total designs: ", designs, "Current design: ", current_design)
            stitches = int(payload[16] + payload[15], 16)-1024
            process_data(payload_dec, stitches)
        else:
            process_data(payload_dec)
        if check_for_dst(payload):
            dst_incoming = True
            first_packet = True
        elif "".join(payload) == "553e554d0a0050505200000000590d00":
            dst_incoming = True
            first_packet = True
        elif not dst_incoming:
            first_packet = False
            dst_incoming = False
        else:
            dst_data = dst_data[1:]
            dst_data = bytes.fromhex("".join(dst_data))
            with open("design.dst", 'wb') as output:
                output.write(dst_data)
                output.close()
            dst_data = []
            first_packet = False
            dst_incoming = False
