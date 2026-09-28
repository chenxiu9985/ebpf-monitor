import json
import struct

MAX_FRAME = 1024 * 1024


def encode(event):
    data = json.dumps(event, ensure_ascii=False).encode("utf-8")
    if not 0 < len(data) <= MAX_FRAME:
        raise ValueError("frame too large")
    return struct.pack("!I", len(data)) + data


class Decoder:
    def __init__(self):
        self.buffer = bytearray()

    def feed(self, data):
        self.buffer.extend(data)
        result = []
        while len(self.buffer) >= 4:
            size = struct.unpack("!I", self.buffer[:4])[0]
            if not 0 < size <= MAX_FRAME:
                raise ValueError("invalid frame length")
            if len(self.buffer) < 4 + size:
                break
            result.append(json.loads(self.buffer[4:4 + size].decode("utf-8")))
            del self.buffer[:4 + size]
        return result

    def finish(self):
        if self.buffer:
            raise ValueError("truncated frame on disconnect")
