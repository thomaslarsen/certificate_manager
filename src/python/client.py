import json

from oscrypto import asymmetric, keys as crypto_keys
from certbuilder import CertificateBuilder, pem_armor_certificate

from asn1crypto import pem, x509
from asn1crypto.csr import CertificationRequest

from flask import current_app
from ca import private_key_filename, NotFoundException, InvalidValueException, encryption_schema, _load_ca, _construct_subject, _construct_ca_chain, _calc_enddate

client_filename = "client"

def _check_role(client, role, subject):
  pass

def _get_client(client):
  if current_app.certmanager.exists(client_filename, path=f"clients/{client}"):
    return json.loads(current_app.certmanager.read_bytes(client_filename, path=f"clients/{client}"))
  else:
    raise NotFoundException(f"{client} client not found")

def _get_client_role(client, role):
  _ = _get_client(client) # Check if client exists

  if current_app.certmanager.exists(role, path=f"clients/{client}/roles/{role}"):
    return json.loads(current_app.certmanager.read_bytes(role, path=f"clients/{client}/roles/{role}"))
  else:
    raise NotFoundException(f"{role} client role not found")

def put_client(client, body):
  def _write_client(value):
    ca = value["ca"]
    if not current_app.secretmanager.exists(private_key_filename, path=ca):
      raise NotFoundException(f"{ca} CA not found")

    current_app.certmanager.write_string(client_filename, json.dumps(value), path=f"clients/{client}")

    return value

  try:
    # Check if client already exists
    if current_app.certmanager.exists(client_filename, path=f"clients/{client}"):
      return _write_client({**_get_client(client), **body}), 200
    else:
      return _write_client(body), 201
  except NotFoundException as e:
    return str(e), 404

def get_client(client):
  try:
    return _get_client(client), 200
  except NotFoundException as e:
    return str(e), 404

def delete_client(client):
  try:
    _ = _get_client(client)

    current_app.certmanager.delete(client, path=f"clients")
  except NotFoundException as e:
    return str(e), 404

def put_role(client, role, body):
  def _write_role(value):
    current_app.certmanager.write_string(role, json.dumps(value), f"clients/{client}/roles/{role}")

    return value

  try:
    _ = _get_client(client)
    if current_app.certmanager.exists(role, path=f"clients/{client}/roles/{role}"):
      return _write_role({**_get_client_role(client, role), **body}), 200
    else:
      return _write_role(body), 201
  except NotFoundException as e:
    return str(e), 404

def get_client_role(client, role):
  try:
    return _get_client_role(client, role), 200
  except NotFoundException as e:
    return str(e), 404

def delete_client_role(client, role):
  try:
    cert_client = _get_client(client)
    cert_role = _get_client_role(client, role)

    current_app.certmanager.delete(role, f"clients/{client}/roles")
  except NotFoundException as e:
    return str(e), 404

def list_client_roles(client):
  try:
    _ = _get_client(client)


    return current_app.certmanager.list(path=f"clients/{client}/roles"), 200

    if current_app.certmanager.exists(f"clients/{client}/roles"):
      return current_app.certmanager.list(path=f"clients/{client}/roles"), 200
    else:
      return [], 200
  except FileNotFoundError:
    return [], 200
  except NotFoundException as e:
    return str(e), 404

def list_clients():
  return current_app.certmanager.list(path=f"clients"), 200

def issue(client, role, body, ttl=None):
  try:
    cert_client = _get_client(client)
    cert_role = _get_client_role(client, role)

    ca = cert_client["ca"]
    signing_ca_certificate, signing_ca_private_key = _load_ca(ca)

    subject = _construct_subject(body, parent=signing_ca_certificate)
    subject = {**subject, **cert_role["subject"]}

    # Check against role
    _check_role(client, role, subject)

    # Extract parameters
    bit_size = int(cert_role["size"])

    # Generate and save the key and certificate for the root CA
    public_key, private_key = asymmetric.generate_pair(encryption_schema, bit_size=bit_size)

    # Create the certificate
    builder = CertificateBuilder(
        subject,
        public_key
    )

    builder.end_date = _calc_enddate(ttl, cert_role.get("max_ttl", current_app.config["CERT_MAX_TTL"]), cert_role.get("default_ttl", current_app.config["CERT_DEFAULT_TTL"]))
    builder.issuer = asymmetric.load_certificate(signing_ca_certificate)
    builder.extended_key_usage = set(["client_auth"])

    certificate = builder.build(asymmetric.load_private_key(signing_ca_private_key, None))

    # Store the certificate in case it needa to be revoked
    # We store it using the serial number as the filename
    filename = subject["common_name"]
    current_app.certmanager.write_bytes(filename, pem_armor_certificate(certificate), path=f"clients/{client}/certs")

    return {
      "certificate": pem_armor_certificate(certificate).decode('utf8'),
      "ca_chain": _construct_ca_chain(certificate, ca),
      "private_key": asymmetric.dump_private_key(private_key, None).decode('utf8')
    }, 201
  except NotFoundException as e:
    return str(e), 404
  except InvalidValueException as e:
    return str(e), 400

def sign(client, role, body, ttl=None, cn=None):
  cert_client = _get_client(client)
  cert_role = _get_client_role(client, role)

  _, _, der_bytes = pem.unarmor(body)
  csr = CertificationRequest.load(der_bytes)

  try:
    ca = cert_client["ca"]
    signing_ca_certificate, signing_ca_private_key = _load_ca(ca)

    # Construct subject
    csr_subject = csr["certification_request_info"]["subject"].native
    if cn:
      csr_subject["common_name"] = cn
    subject = _construct_subject(csr_subject, parent=signing_ca_certificate)
    subject = {**subject, **cert_role["subject"]}

    # Check against role
    _check_role(client, role, subject)

    # Create the certificate
    builder = CertificateBuilder(
      subject,
      csr["certification_request_info"]["subject_pk_info"]
    )

    builder.end_date = _calc_enddate(ttl, cert_role.get("max_ttl", current_app.config["CERT_MAX_TTL"]), cert_role.get("default_ttl", current_app.config["CERT_DEFAULT_TTL"]))
    builder.issuer = asymmetric.load_certificate(signing_ca_certificate)
    builder.extended_key_usage = set(["client_auth"])

    certificate = builder.build(asymmetric.load_private_key(signing_ca_private_key, None))

    # Store the certificate in case it needa to be revoked
    # We store it using the serial number as the filename
    filename = subject["common_name"]
    current_app.certmanager.write_bytes(filename, pem_armor_certificate(certificate), path=f"clients/{client}/certs")

    return {
      "certificate": pem_armor_certificate(certificate).decode('utf8'),
      "ca_chain": _construct_ca_chain(certificate, ca)
    }, 201
  except NotFoundException as e:
    return str(e), 404
  except InvalidValueException as e:
    return str(e), 400

def get_cert(client, cert):
  try:
    cert_client = _get_client(client)
    ca = cert_client["ca"]

    if not current_app.certmanager.exists(cert, path=f"clients/{client}/certs"):
      raise NotFoundException(f"{client} client cert CN={cert} not found")

    certificate = current_app.certmanager.read_bytes(cert, path=f"clients/{client}/certs")

    return {
      "certificate": certificate.decode('utf8'),
      "ca_chain": _construct_ca_chain(crypto_keys.parse_certificate(certificate), ca)
    }, 200
  except NotFoundException as e:
    return str(e), 404
  except InvalidValueException as e:
    return str(e), 400

def delete_cert(client, cert):
  try:
    cert_client = _get_client(client)

    if not current_app.certmanager.exists(cert, path=f"clients/{client}/certs"):
      raise NotFoundException(f"{client} client cert CN={cert} not found")

    current_app.certmanager.delete(cert, path=f"clients/{client}/certs")

  except NotFoundException as e:
    return str(e), 404
  except InvalidValueException as e:
    return str(e), 400
