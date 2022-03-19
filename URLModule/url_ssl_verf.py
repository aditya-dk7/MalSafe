# -*- encoding: utf-8 -*-
# requires a recent enough python with idna support in socket
# pyopenssl, cryptography and idna

from OpenSSL import SSL
from cryptography import x509
from cryptography.x509.oid import NameOID
import idna
import ssl
import re
import web_scraper
from threading import Thread
import queue


from socket import socket, AF_INET, timeout
from collections import namedtuple

HostInfo = namedtuple(field_names='cert hostname peername', typename='HostInfo')


def verify_cert(cert, hostname):
    # verify notAfter/notBefore, CA trusted, servername/sni/hostname
    cert.has_expired()
    # service_identity.pyopenssl.verify_hostname(client_ssl, hostname)
    # issuer

def get_certificate(hostname, port):
    hostname_idna = idna.encode(hostname)
    sock = socket()

    sock.connect((hostname, port))
    peername = sock.getpeername()
    ctx = SSL.Context(SSL.SSLv23_METHOD) # most compatible
    ctx.check_hostname = False
    ctx.verify_mode = SSL.VERIFY_NONE

    sock_ssl = SSL.Connection(ctx, sock)
    sock_ssl.set_connect_state()
    sock_ssl.set_tlsext_host_name(hostname_idna)
    sock_ssl.do_handshake()
    cert = sock_ssl.get_peer_certificate()
    crypto_cert = cert.to_cryptography()
    sock_ssl.close()
    sock.close()

    return HostInfo(cert=crypto_cert, peername=peername, hostname=hostname)

def get_alt_names(cert):
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        return ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        return None

def get_common_name(cert):
    try:
        names = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        return names[0].value
    except x509.ExtensionNotFound:
        return None

def get_issuer(cert):
    try:
        names = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
        return names[0].value
    except x509.ExtensionNotFound:
        return None


def print_basic_info(hostinfo):
    s = '''» {hostname} « … {peername}
    \tcommonName: {commonname}
    \tSAN: {SAN}
    \tissuer: {issuer}
    \tnotBefore: {notbefore}
    \tnotAfter:  {notafter}
    '''.format(
            hostname=hostinfo.hostname,
            peername=hostinfo.peername,
            commonname=get_common_name(hostinfo.cert),
            SAN=get_alt_names(hostinfo.cert),
            issuer=get_issuer(hostinfo.cert),
            notbefore=hostinfo.cert.not_valid_before,
            notafter=hostinfo.cert.not_valid_after
    )
    print(s)

def json_print_basic_info(hostinfo):
    basic_info ={}
    basic_info['hostname'] = hostinfo.hostname
    basic_info['peername'] = hostinfo.peername
    basic_info['commonname'] = get_common_name(hostinfo.cert)
    basic_info['SAN'] = get_alt_names(hostinfo.cert)
    basic_info['issuer'] = get_issuer(hostinfo.cert)
    basic_info['notbefore'] = hostinfo.cert.not_valid_before
    basic_info['notafter'] = hostinfo.cert.not_valid_after
    return basic_info

def check_it_out(hostname, port):
    hostinfo = get_certificate(hostname, port)
    print_basic_info(hostinfo)

def refactorUrl(url):
    newUrl = re.findall(r"^(?:https?:\/\/)?(?:[^@\n]+@)?(?:www\.)?([^:\/\n?]+)",url)[0]
    if(newUrl.startswith("https://")):
        newUrl = newUrl.replace("https://","")
    return str(newUrl)

def url_cert_info(hostname1):
    hostname = refactorUrl(hostname1)
    context = ssl.create_default_context()
    conn = context.wrap_socket(socket(AF_INET), server_hostname=hostname)
    conn.settimeout(5.0)
    final_url_info = {}
    try:
        conn.connect((hostname, 443))
        #print("[+]The url has SSL Certificate, and website uses HTTPS.")
        #print("Printing common information:")
        #print_basic_info(get_certificate(hostname, 443))
        final_url_info['urlInfo'] = json_print_basic_info(get_certificate(hostname, 443))
    except ssl.CertificateError:
        # print("[-]The url '" + hostname + "' certificates fail to match similar alternative names. The URL has certificate error.")
        # print("Printing common information:")
        # print_basic_info(get_certificate(hostname, 443))
        final_url_info['urlInfo'] = json_print_basic_info(get_certificate(hostname, 443))
    except timeout:
        #print("[-]Unable to gather SSL Certificate information, most likely HTTP. Skipping common information.")
        final_url_info['urlInfo'] = "Unable to gather SSL Certificate information, most likely HTTP. Skipping common information."
    myQueue = queue()
    Thread(target = web_scraper.scraper(hostname1)).start()
    # Thread(target = web_scraper.load_animation()).start()
    # print("\n")
    # Thread(target = web_scraper.print_target_links()).start()
    # print("\n")
    t = Thread(web_scraper.call_sql_vul_check(myQueue))
    t.start()
    t.join()
    val = myQueue.get()
    final_url_info['sqlVul'] = val
    return final_url_info
    