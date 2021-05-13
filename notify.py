import sys
import pyshark
import constant
import functions


# get arguments with defaults
pc_ip = sys.argv[1] or constant.IP_PC
machine_ip = sys.argv[2] or constant.IP_MACHINE
port = sys.argv[3] or constant.COMMUNICATION_PORT

# reset and define variables
dst_data = []
dst_incoming = False
first_packet = False

# create capture object
cap = pyshark.LiveCapture(None, bpf_filter="tcp port " + str(port))

# iterate captured packets
for packet in cap.sniff_continuously():

    # if the packet has a payload, and the packet originates from the PC (indicating a DST is being sent to the machine)
    if packet[1].src == pc_ip and hasattr(packet.tcp, 'payload'):

        # split the payload into an array of bytes in hex notation
        payload = packet.tcp.payload.split(':')

        # if the script detects a DST design is being sent (set on line 92)
        if dst_incoming:

            # and if the current packet is the first packet of the DST design (set on line 93)
            if first_packet:

                # remove the first 12 bytes from the payload (indicating that a DST is being sent)
                payload = payload[12:]

                # set this variable as false, so
                first_packet = False

            # if the packet has an 'end of packet' indicator remove it
            if functions.check_for_end_of_packet(payload):
                payload = payload[:len(payload)-3]

            # iterate through the bytes of the payload
            for i in range(0, len(payload)):

                # if i is the third from last element in the payload, and the last three bytes in the payload are EOF
                if i+2 < len(payload)-1 and payload[i] == "00" and payload[i+1] == "00" and payload[i+2] == "f3":

                    # append the DST equivalent of EOF to the DST data
                    dst_data.append(constant.DST_EOF)
                    dst_incoming = False
                    first_packet = False
                    break

                # otherwise append the current byte to the DST data.
                dst_data.append(payload[i])

    # if the packet originates from the machine, and it has a payload
    if packet[1].src == machine_ip and hasattr(packet.tcp, 'payload'):

        # split the payload into an array of bytes in hex notation
        payload = packet.tcp.payload.split(':')
        payload_dec = []

        # convert the hexadecimal bytes to decimal notation (eg. 1a => 26)
        for hex_number in payload:
            payload_dec.append(int(hex_number, 16))

        # if the payload contains exactly 21 bytes
        if len(payload) == 21:

            # extract the number of designs
            designs = int(payload[constant.NUMBER_OF_DESIGNS_BYTE])

            # extract the current design
            current_design = int(payload[constant.CURRENT_DESIGN_BYTE])+1

            # extract the current stitch index
            stitches = int(payload[16] + payload[15], 16)-1024

            # echo results
            print("Total designs: " + str(designs) +
                  ", current design: " + str(current_design) +
                  ", current stitch: " + str(stitches)
                  )
        else:
            # get the state from the decimal data
            state = functions.parse_ctrl_word(payload_dec)

            # echo result
            print("Current state: " + state)

        # if the payload indicates that a DST design is being requested then flip the variables so when the PC sends the
        # design we can intercept it
        if functions.check_for_dst(payload):
            dst_incoming = True
            first_packet = True

        # if dst_incoming is set to False then reset
        elif not dst_incoming:
            first_packet = False

        # otherwise write the DST design to a file
        else:

            # drop the first byte
            dst_data = dst_data[1:]
            dst_data = bytes.fromhex("".join(dst_data))
            with open("design.dst", 'wb') as output:
                output.write(dst_data)
                output.close()

            # reset
            dst_data = []
            first_packet = False
            dst_incoming = False
