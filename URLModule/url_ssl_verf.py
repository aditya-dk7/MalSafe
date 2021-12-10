import sys
import socket
import ssl
import datetime


#This function is made to check the ssl certificate and print it's details
def check_ssl(hostname):
    print(hostname)
    ssl_date_fmt = r'%b %d %H:%M:%S %Y %Z'
    context = ssl.create_default_context()
    conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=hostname)
    conn.settimeout(5.0)
    try:
        conn.connect((hostname, 443))
        ssl_info = conn.getpeercert()
        for v in ssl_info['subject']:
            print(v[0][0], ':', v[0][1])
        exp = datetime.datetime.strptime(ssl_info['notAfter'], ssl_date_fmt)
        no_days_remaining = exp - datetime.datetime.utcnow()
        print("Expires On: ", str(exp))
        print("Days Remaining: ", str(no_days_remaining))
    except socket.gaierror:
        print("[-]Connection establishment failure. Please check your internet connection and website url")
    except ssl.SSLCertVerificationError:
        print("[-]Warning, the connection does not support HTTPS")
    except ConnectionRefusedError:
        print("[-]Warning, the connection does not support HTTPS")
    except ConnectionResetError:
        print("[-]Warning, the connection does not support HTTPS")       

    except socket.timeout:
        print("[-]Connection timed out")
        print("This happens sometimes, please re-run the script")
        sys.exit(0)



