from .defines import WATags, WASingleByteTokens, WADoubleByteTokens, WAWebMessageInfo


class WABinaryReader:
    """WhatsApp Binary Reader
    Read binary data from WhatsApp stream protocol
    """

    def __init__(self, data):
        self.data = data
        self.index = 0

    def check_eos(self, length):
        """Check if the end of the stream has been reached"""
        if self.index + length > len(self.data):
            raise EOFError("end of stream reached")

    def read_byte(self):
        """Read single byte from the stream"""
        self.check_eos(1)
        ret = ord(chr(self.data[self.index]))
        self.index += 1
        return ret

    def read_int_n(self, n, littleEndian=False):
        """Read integer value of n bytes"""
        self.check_eos(n)
        ret = 0
        for i in range(n):
            currShift = i if littleEndian else n - 1 - i
            ret |= ord(chr(self.data[self.index + i])) << (currShift * 8)
        self.index += n
        return ret

    def read_int16(self, littleEndian=False):
        """Read 16-bit integer value"""
        return self.read_int_n(2, littleEndian)

    def read_int20(self):
        """Read 20-bit integer value"""
        self.check_eos(3)
        ret = ((ord(chr(self.data[self.index])) & 15) << 16) + (ord(chr(self.data[self.index + 1])) << 8) + ord(chr(
            self.data[self.index + 2]))
        self.index += 3
        return ret

    def read_int32(self, littleEndian=False):
        """Read 32-bit integer value"""
        return self.read_int_n(4, littleEndian)

    def read_int64(self, littleEndian=False):
        """Read 64-bit integer value"""
        return self.read_int_n(8, littleEndian)

    def read_packed8(self, tag):
        """Read packed 8-bit string"""
        startByte = self.read_byte()
        ret = ""
        for i in range(startByte & 127):
            currByte = self.read_byte()
            ret += self.unpack_byte(tag, (currByte & 0xF0)
                                    >> 4) + self.unpack_byte(tag, currByte & 0x0F)
        if (startByte >> 7) != 0:
            ret = ret[:len(ret) - 1]
        return ret

    def unpack_byte(self, tag, value):
        """Handle byte as nibble digit or hex"""
        if tag == WATags.NIBBLE_8:
            return self.unpack_nibble(value)
        elif tag == WATags.HEX_8:
            return self.unpack_hex(value)

    def unpack_nibble(self, value):
        """Convert value to digit or special chars"""
        if 0 <= value <= 9:
            return chr(ord('0') + value)
        elif value == 10:
            return "-"
        elif value == 11:
            return "."
        elif value == 15:
            return "\0"
        raise ValueError("invalid nibble to unpack: " + value)

    def unpack_hex(self, value):
        """Convert value to hex number"""
        if value < 0 or value > 15:
            raise ValueError("invalid hex to unpack: " + str(value))
        if value < 10:
            return chr(ord('0') + value)
        else:
            return chr(ord('A') + value - 10)

    def is_list_tag(self, tag):
        """Check if the given tag is a list tag"""
        return tag == WATags.LIST_EMPTY or tag == WATags.LIST_8 or tag == WATags.LIST_16

    def read_list_size(self, tag):
        """Read the size of a list"""
        if (tag == WATags.LIST_EMPTY):
            return 0
        elif (tag == WATags.LIST_8):
            return self.read_byte()
        elif (tag == WATags.LIST_16):
            return self.read_int16()
        raise ValueError("invalid tag for list size: " + str(tag))

    def read_string(self, tag):
        """Read a string from the stream depending on the given tag"""
        if tag >= 3 and tag <= 235:
            token = self.get_token(tag)
            if token == "s.whatsapp.net":
                token = "c.us"
            return token

        if tag == WATags.DICTIONARY_0 or tag == WATags.DICTIONARY_1 or tag == WATags.DICTIONARY_2 or tag == WATags.DICTIONARY_3:
            return self.get_token_double(tag - WATags.DICTIONARY_0, self.read_byte())
        elif tag == WATags.LIST_EMPTY:
            return
        elif tag == WATags.BINARY_8:
            return self.read_string_from_chars(self.read_byte())
        elif tag == WATags.BINARY_20:
            return self.read_string_from_chars(self.read_int20())
        elif tag == WATags.BINARY_32:
            return self.read_string_from_chars(self.read_int32())
        elif tag == WATags.JID_PAIR:
            i = self.read_string(self.read_byte())
            j = self.read_string(self.read_byte())
            if i is None or j is None:
                raise ValueError("invalid jid pair: " + str(i) + ", " + str(j))
            return i + "@" + j
        elif tag == WATags.NIBBLE_8 or tag == WATags.HEX_8:
            return self.read_packed8(tag)
        else:
            raise ValueError("invalid string with tag " + str(tag))

    def read_string_from_chars(self, length):
        """Read indexed string from the stream with the given length"""
        self.check_eos(length)
        ret = self.data[self.index:self.index + length]
        self.index += length
        return ret

    def read_attributes(self, n):
        """Read n data attributes"""
        ret = {}
        if n == 0:
            return
        for i in range(n):
            index = self.read_string(self.read_byte())
            ret[index] = self.read_string(self.read_byte())
        return ret

    def read_list(self, tag):
        """Read a list of data"""
        ret = []
        for i in range(self.read_list_size(tag)):
            ret.append(self.read_node())
        return ret

    def read_node(self):
        """Read an information node"""
        listSize = self.read_list_size(self.read_byte())
        descrTag = self.read_byte()
        if descrTag == WATags.STREAM_END:
            raise ValueError("unexpected stream end")
        descr = self.read_string(descrTag)
        if listSize == 0 or not descr:
            raise ValueError("invalid node")
        attrs = self.read_attributes((listSize - 1) >> 1)
        if listSize % 2 == 1:
            return [descr, attrs, None]

        tag = self.read_byte()
        if self.is_list_tag(tag):
            content = self.read_list(tag)
        elif tag == WATags.BINARY_8:
            content = self.read_bytes(self.read_byte())
        elif tag == WATags.BINARY_20:
            content = self.read_bytes(self.read_int20())
        elif tag == WATags.BINARY_32:
            content = self.read_bytes(self.read_int32())
        else:
            content = self.read_string(tag)
        return [descr, attrs, content]

    def read_bytes(self, n):
        """Read n bytes from the stream and return them as a string"""
        ret = ""
        for i in range(n):
            ret += chr(self.read_byte())
        return ret

    def get_token(self, index):
        """Get the token at the given index."""
        if index < 3 or index >= len(WASingleByteTokens):
            raise ValueError("invalid token index: " + str(index))
        return WASingleByteTokens[index]

    def get_token_double(self, index1, index2):
        """Get a token from a double byte index"""
        n = 256 * index1 + index2
        if n < 0 or n >= len(WADoubleByteTokens):
            raise ValueError("invalid token index: " + str(n))
        return WADoubleByteTokens[n]


def read_message_array(msgs):
    """Read a list of messages"""
    if not isinstance(msgs, list):
        return msgs
    ret = []
    for x in msgs:
        ret.append(WAWebMessageInfo.decode(bytes(x[2], "utf-8")) if isinstance(
            x, list) and x[0] == "message" else x)
    return ret


def read_binary(data, withMessages=False):
    """Read a binary message from WhatsApp stream"""
    node = WABinaryReader(data).read_node()
    if withMessages and node is not None and isinstance(node, list) and node[1] is not None:
        node[2] = read_message_array(node[2])
    return node
