import constant


# parse control word
def parse_ctrl_word(data):

    # check for running state
    if data[constant.STATE_WORD_BYTE_1] == constant.STATE_RUNNING_FIRST and \
            data[constant.STATE_WORD_BYTE_2] == constant.STATE_RUNNING_SECOND:
        return constant.STATE_RUNNING

    # check for end state
    elif data[constant.STATE_WORD_BYTE_1] == constant.STATE_END_FIRST and \
            data[constant.STATE_WORD_BYTE_2] == constant.STATE_END_SECOND:
        return constant.STATE_END

    # check other states
    elif data[constant.STATE_WORD_BYTE_1] == constant.STATE_OTHER_FIRST:
        return constant.STATE_WORD_STATE_MAP.get(data[constant.STATE_WORD_BYTE_2], constant.STATE_INVALID)


# check incoming data if its a dst file
def check_for_dst(data):
    return \
        data[len(data)-7] == constant.DST_CHECK[0] and \
        data[len(data)-8] == constant.DST_CHECK[1] and \
        data[len(data)-9] == constant.DST_CHECK[2] and \
        data[8] == constant.DST_CHECK[3] or \
        "".join(data) == constant.DST_REQUEST


# check whether incoming data is the end of the packet
def check_for_end_of_packet(data):
    return \
        data[len(data)-1] == constant.EOP_CHECK[0] and \
        data[len(data)-2] == constant.EOP_CHECK[1] and \
        data[len(data)-3] == constant.EOP_CHECK[2]


# check whether incoming data is the start of a packet
def check_for_start(data):
    for i in range(2, len(data)-1):
        if \
                data[i] == constant.PACKET_START_CHECK[0] and \
                data[i-1] == constant.PACKET_START_CHECK[1] and \
                data[i-2] == constant.PACKET_START_CHECK[2]:
            return i
