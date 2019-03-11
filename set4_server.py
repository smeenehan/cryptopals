from time import sleep

from flask import Flask, request

from crypto.hash import HMAC
from crypto.utils import hex_to_bytes

SECRET_KEY = b'YELLOW SUBMARINE'
SLEEP_TIME = 0.001
HMAC_LEN = 4

def insecure_compare(test_sig, real_sig):
    for tb, rb in zip(test_sig, real_sig):
        if tb != rb:
            return False
        sleep(SLEEP_TIME)
    return True

app = Flask(__name__)

@app.route('/')
def basic_response():
    return 'OK', 200

@app.route('/test')
def verify_hmac():

    if request.method == 'GET':
        file = request.args.get('file').encode()
        signature = hex_to_bytes(request.args.get('signature'))
        file_sig = HMAC(SECRET_KEY, file)
        if insecure_compare(signature[:HMAC_LEN], file_sig[:HMAC_LEN]):
            return 'OK', 200
        else:
            return 'BAD', 500

def main():
    app.run(port=8082)

if __name__ == '__main__':
    main()
