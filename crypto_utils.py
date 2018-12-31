import base64

def hex_to_bytes(hex_string):
    return bytearray.fromhex(hex_string)

def bytes_to_hex(byte_array):
    return bytearray.hex(byte_array)

def base64_to_bytes(base64_string):
    return bytearray(base64.b64decode(base64_string))

def bytes_to_base64(byte_array):
    return base64.b64encode(byte_array).decode('utf-8')

def hex_to_base64(hex_string):
    return bytes_to_base64(hex_to_bytes(hex_string))

def base64_to_hex(base64_string):
    return bytes_to_hex(base64_to_bytes(base64_string))
