
import base64
import datetime
import functools
import json
import socket

from flask import current_app, Blueprint, jsonify, request, make_response

from ..exceptions import ConfigurationError

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization

import cryptography.x509 as x509

import htcondor2 as htcondor

ca_bp = Blueprint(
    "ca",
    __name__,
)


@functools.lru_cache()
def get_ca_cert_key():

    ca_filename = current_app.config.get("CA_CERTFILE", "/etc/pki/rsyslog-ca/tls.crt")
    cakey_filename = current_app.config.get("CA_KEYFILE", "/etc/pki/rsyslog-ca/tls.key")

    with open(ca_filename, "rb") as fp:
        ca = x509.load_pem_x509_certificate(fp.read())

    with open(cakey_filename, "rb") as fp:
        cakey = serialization.load_pem_private_key(fp.read(), password=None)

    return ca, cakey


# Instead of setting up proper caching, I simply do an LRU from functools and
# add the date to the arguments.  This way, we'll do the lookup at the collector
# once a day.
@functools.lru_cache(maxsize=256)
def ping_authz(token, today):
    collector = current_app.config.get("COLLECTOR", "cm-1.ospool.osg-htc.org")

    # We are sufficiently friendly with the CHTC collector that, if we see a token from there,
    # use that collector instead of the OSG one.  This allows CHTC glideins to send logs to the
    # OSPool syslog service.  Mostly, this allows testing without disturbing the OSPool.
    token_pieces = token.split(".")
    if len(token_pieces) == 3:
        try:
            payload = base64.b64decode(token_pieces[1] + "="*(4 - (len(token_pieces[1]) % 4)))
            payload = json.loads(payload)
            if payload.get("iss") == "cm.chtc.wisc.edu":
                collector = "glidein-cm.chtc.wisc.edu"
        except:
            pass

    addrs = socket.getaddrinfo(collector, 9618, socket.AF_INET, socket.SOCK_STREAM)[0][-1]
    myaddr = f"<{addrs[0]}:{addrs[1]}>"

    security = htcondor.SecurityContext(token=token)
    return dict(htcondor.ping(myaddr, security=security))


@ca_bp.route("/syslog-ca/issue", methods=["POST"])
def connect():

    authorization = request.headers.get("Authorization")
    if not authorization:
        return make_response(jsonify(err="Endpoint requires authorization"), 401)
    authz_info = authorization.split()
    if len(authz_info) != 2 or authz_info[0].strip().lower() != "bearer":
        return make_response(jsonify(err="Endpoint requires bearer token"), 401)

    try:
        authz_info = ping_authz(authz_info[1].strip(), datetime.date.today())

        if authz_info.get("AuthMethods") != "TOKEN" or authz_info.get("Authentication") != "YES" or \
                authz_info.get("AuthorizationSucceeded") != True or not authz_info.get("MyRemoteUserName"):
            return make_response(jsonify(err="Remote authz server returned unexpected response"), 403)
    except Exception as exc:
        return make_response(jsonify(err="Failed to ping remote auth server", exc=str(exc)), 403)

    form_csr = request.form.get("csr")
    if not form_csr:
        return make_response(jsonify(err="CSR request not provided"), 400)

    try:
        ca, cakey = get_ca_cert_key()
    except Exception as exc:
        return make_response(jsonify(err="Failed to load local key material", exc=str(exc)), 500)

    try:
        csr = x509.load_pem_x509_csr(form_csr.encode('utf-8'))
    except Exception as exc:
        return make_response(jsonify(err="Failed to parse provided CSR", exc=str(exc)), 400)

    one_day = datetime.timedelta(1, 0, 0)

    try:
        username = authz_info.get("MyRemoteUserName")
        builder = x509.CertificateBuilder(
           ).subject_name(x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, username)])
           ).issuer_name(ca.subject
           ).not_valid_before(datetime.datetime.today() - one_day
           ).not_valid_after(datetime.datetime.today() + (one_day * 30)
           ).serial_number(x509.random_serial_number()
           ).public_key(csr.public_key()
           ).add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True
           ).add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]), critical=True)

        x509_obj = builder.sign(private_key=cakey, algorithm=hashes.SHA256())

        return jsonify(certificate=x509_obj.public_bytes(serialization.Encoding.PEM).decode(),
                       ca=ca.public_bytes(serialization.Encoding.PEM).decode())
    except Exception as exc:
        return make_response(jsonify(err="Internal error when building certificate", exc=str(exc)), 500)
