#!/usr/bin/python

import time
import BaseHTTPServer
import urlparse
from Crypto.Cipher import ARC4
import sys

LISTEN_ADDR = '192.168.255.1' # You probably need to change this. Just sayin
LISTEN_PORT = 80

def Post2Key( post ):
    for i in range(1,len(post)):
        keylist = []
        secretcode = ""
        key = post
        for i in range(len(key)):
          keylist.append(key[i])
        while keylist:
          if len(keylist) == 1:
                secretcode = secretcode + keylist[0]
                break;
          if (ord(keylist[0]) > ord(keylist[1])):
                secretcode = secretcode + keylist[1]
                keylist.remove(keylist[1])
          else:
                secretcode = secretcode + keylist[0]
                keylist.remove(keylist[0])
        post = secretcode
    return secretcode

class MyHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    protocol_version="HTTP/1.1"
    server_version="Apache/2.2.15"
    sys_version="(CentOS)"

    def log_message(slef, format, *args):
        return

    def do_POST(s):
        length = int(s.headers['Content-Length'])
        post_data = urlparse.parse_qs(s.rfile.read(length).decode('utf-8'))
        for key, value in post_data.iteritems():

            # Get the coded key from the URL
            code = str(s.path).strip("/")
            # Decode the value into a crypt key
            dkey = Post2Key(code)
            # Get the post value from the request
            dataraw=value[0].decode('utf-8')
            # The post is in HEX, change to ASCII
            data = dataraw.decode('hex')
            # Create a new crypto object
            rc4 = ARC4.new(dkey)
            # Decrypt the message
            info = rc4.decrypt(data)
            # Break out the operation type
            opmessy = info.split('|')
            op = opmessy[0].strip("{")

            # If the operation is 1, this is an initial checkin.
            # Send back an ID
            if op == "1":
                phase = "Initial Checkin"
                response="{176|1}"
            # If the operation is 7, this is something else
            elif op == "7":
                # If the message contains "all" then it's a beacon.
                # Respond with nothing!
                phase = "Post Crypt Beacon"
                beacon = info.find("all")
                response = ""
                # If the message is not a beacon, must be a request for a key.
                # Respond with a random pub key and dummy ID values.
                if beacon == -1:
                    phase = "Fetch Pub Key"
                    response="""{220|random.site.int|6EiL|US|-----BEGIN PUBLIC K                                                                                                                                                             EY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1qg3oecbKebESucJGzA2
nEnTlf5w88UrYM8Rgl24L+ozsERvknnvFpdLbBVQDVUDkju3gSZeRcm22acFssIl
j5rapzp96dnjFxtoxazgNcOfoNFhVvlcPouo0GICEJZJlwb7REMxzKr4ghXRLqnS
nv+XWsNsmkQPQVokrWsoCsXt0mPSy2Sx5ojztlCZsoRTijhLnQHBizingYhTrjj6
gknux/JibZTlYhCJz59VpqZkGRYQ/PDZXwXxpa8DikckDvP9uC1LVqoxhjB9ePUr
Wty+BfaSTODAg2MjuLl7NwhDZppZu6AlV+1v200cDVi/xg+OxP2Lc0Hz6Pk85ilv
AQIDAQAB
-----END PUBLIC KEY-----}"""

            # Output some info
            print "-----------------------------------"
            print phase
            print "-----------------------------------"
            print "Serving Host: %s" % s.headers.get('Host')
            print "Crypt key: %s" % dkey
            print "Information: %s" % info
            print "Clear Response: %s" % response

        # Encode the response with the same key and convert to HEX
        rc42 = ARC4.new(dkey)
        encoded=rc42.encrypt(response)
        text=encoded.encode("hex")

        # Send the reponse. Took the time to recreate the real malware
        # HTTP response, but it looks like it doesn't check!
        s.send_response(200)
        s.send_header("X-Powered-By", "PHP/5.4.30")
        s.send_header("Expires", "Sat, 26 Jul 1997 05:00:00 GMT")
        s.send_header("Last-Modified", "Thu, 01 Jan 1970 02:46:40 GMT")
        s.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
        s.send_header("Cache-Control", "post-check=0, pre-check=0")
        s.send_header("Pragma", "no-cache")
        s.send_header("Content-Length", str(len(text)))
        s.send_header("Content-Type", "text/html; charset=utf-8")
        s.send_header("Connection", "close")
        s.end_headers()
        s.wfile.write(text)

        # Leftover from debugging - decrypt the response to make sure the
        # encryption was correct.
        rc43 = ARC4.new(dkey)
        checkraw = text.decode("hex")
        check = rc43.decrypt(text.decode("hex"))
        #print "Check: %s" % check
        print "-----------------------------------"

if __name__ == '__main__':
    server_class = BaseHTTPServer.HTTPServer
    httpd = server_class((LISTEN_ADDR, LISTEN_PORT), MyHandler)
    print time.asctime(), "Server Starts - %s:%s" % (LISTEN_ADDR, LISTEN_PORT)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
    print time.asctime(), "Server Stops - %s:%s" % (LISTEN_ADDR, LISTEN_PORT)
