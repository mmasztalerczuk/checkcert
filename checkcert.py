import ssl
import pprint
import socket
import getopt
import sys
import os.path

debug_mode = False
full_chain_mode = False

def print_d(text):
    if debug_mode:
        print(text)

def usage():
    print("Usage: checkcert [OPTION] [FILE]")
    print()
    print("\t-d, --debug\t\t Run in debug mode")
    print("\t-f, --full\t\t Print entire chain")

def create_context():
    print_d("Creating context")
    context = ssl.create_default_context()
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True
    context.load_verify_locations("/etc/ssl/certs/ca-certificates.crt")
    print_d("Context created")
    return context

def connect(context, host_name):
    print_d("Connecting")

    conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=host_name)

    try:
        conn.connect((host_name, 443))
    except Exception as e:
        print(e)
        response = False
    else:
        der_cert = conn.getpeercert()
        nice_print(host_name, der_cert, conn.cipher())

def find_value(v, name):
    if isinstance(v, tuple) and v[0] == name:
        return v[1]

    for item in v:
        if isinstance(item, tuple):
            for i in item:
                ret = find_value(i, name)
                if ret != None:
                    return ret

    return None

def nice_print(host_name, cert, cipher):
    subject = find_value(cert['subject'], 'commonName')
    notAfter = cert['notAfter']
    issuer = find_value(cert['issuer'], 'commonName')
    l = [host_name, subject, issuer, notAfter]
    print("".join(word.ljust(35) for word in l))

if __name__ == '__main__':

    try:
        opts, args = getopt.getopt(sys.argv[1:], 'df:h', ['debug', 'full', 'help'])

    except getopt.GetoptError as e:
        print(e)
        print()
        usage()
        sys.exit(3)
    for opt, arg in opts:
        if opt in ('-h', '--help'):
            usage()
            sys.exit(0)
        elif opt in ('-d', '--debug'):
            debug_mode = True
        elif opt in ('-f', '--full'):
            full_chain_mode = True
        else:
            usage()
            sys.exit(2)

    l = ["NAME", "SUBJECT", "ISSUER", "EXPIRES"]
    print("".join(word.ljust(35) for word in l))
    if os.path.isfile(args[0]):
        with open(args[0], 'r') as file:
            for line in file:
                connect(create_context(), line.rstrip())
