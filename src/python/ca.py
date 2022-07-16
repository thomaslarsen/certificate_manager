from oscrypto import asymmetric, keys as crypto_keys
from certbuilder import CertificateBuilder, pem_armor_certificate

from flask import current_app

from datetime import datetime, timedelta, timezone

# Defaults
encryption_schema = 'rsa'
private_key_filename = "private"
parent_ca_filename = "parent"

class NotFoundException(Exception):
  pass

class InvalidValueException(Exception):
  pass

def _calc_enddate(cert_ttl, max_ttl=None, default_ttl=None):
  """
  Calculate the end date for a certificate given a requested TTL

  :param cert_ttl:
    The requested TTL (in hours) for the certificate
    If None, the default TTL is used

  :param max_ttl:
    The maximum TTL the certificate can be issued with

  :param default_ttl:
    The TTL value used if no specific TTL is requested

  :return:
    The certificated end date
  """
  if cert_ttl:
    if max_ttl and cert_ttl > max_ttl:
      raise InvalidValueException(f"Requested {cert_ttl} TTL is larger than max allowed TTL {max_ttl}")
    ttl = cert_ttl
  else:
    ttl = default_ttl if default_ttl else current_app.config["CERT_DEFAULT_TTL"]

  return (datetime.now() + timedelta(hours=int(ttl))).replace(tzinfo=timezone.utc)

def _construct_subject(body, parent=None, inherit_parent=True):
  """
  Constructs the subject for a certificate

  Fields missing will be copied from the parent if required.

  :param body:
    Dict with the supplied certificate subject details

  :param parent:
    The parent (or issuing CA) certificate.

  :param inherit_parent:
    Set to True to inherit missing subject fields from the parent certificate

  :return:
    Dict with new certificate subject

  """
  subject = {
    "common_name": body["common_name"]
  }

  parent_subject = crypto_keys.parse_certificate(parent).subject.native if parent else None

  for s in [
    "organization_name", "locality_name", "locality_name", "state_or_province_name", "country_name",
    "organizational_unit_name", "email_address", "street_address", "postal_code", "business_category", "incorporation_locality", "incorporation_state_or_province", "incorporation_country",
    "surname", "title", "serial_number", "name", "given_name", "initials", "generation_qualifier", "dn_qualifier", "pseudonym", "domain_component"
    ]:
    if s in body and body[s]:
      subject[s] = body[s]
    else:
      if inherit_parent and parent_subject and s in parent_subject:
        subject[s] = parent_subject[s]

  return subject

def _construct_ca_chain(cert, parent=None):
  """
  Construct the certificate chain, including the CA certs

  :param cert:
    The certificate to construct the chain for

  :param parent:
    The parent CA, which has signed the certificate

  :return:
    A string containing the certificate chain in PEM format
  """
  # Add the certificate to the top of the chain
  ca_chain = pem_armor_certificate(cert).decode('utf8')

  if parent:
    current_parent = parent
    while True:
      parent_cert = current_app.certmanager.read_bytes(current_parent)
      ca_chain += parent_cert.decode('utf8')

      if current_app.secretmanager.exists(parent_ca_filename, path=current_parent):
        current_parent = current_app.secretmanager.read_string(parent_ca_filename, path=current_parent)
      else:
        break

  return ca_chain


def _load_ca(ca):
  """
  Load the certificate and private key for a CA

  :param ca:
    The name of the CA to load

  :return:
    Tuple containing the certificate and private key in PEM format
  """
  if current_app.secretmanager.exists(private_key_filename, path=ca):
    return current_app.certmanager.read_bytes(ca), current_app.secretmanager.read_bytes(private_key_filename, path=ca)
  else:
    raise NotFoundException(f"{ca} CA not found")


############################
#### API calls
############################
def list():
  return current_app.secretmanager.list(), 200

def get_ca(ca):
  try:
    ca_certificate, _ = _load_ca(ca)

    if current_app.secretmanager.exists(parent_ca_filename, path=ca):
      parent = current_app.secretmanager.read_string(parent_ca_filename, path=ca)
    else:
      parent = None

    return {
      "certificate": ca_certificate.decode("utf-8"),
      "ca_chain": _construct_ca_chain(asymmetric.load_certificate(ca_certificate), parent)
    }, 200
  except NotFoundException as e:
    return str(e), 404

def delete_ca(ca):
  # Check if the private key for CA exists
  if not current_app.secretmanager.exists(private_key_filename, path=ca):
    return f"CA {ca} doesn't exist", 404

  current_app.secretmanager.delete(ca)
  current_app.certmanager.delete(ca)

def get_cert(ca):
  try:
    ca_certificate, _ = _load_ca(ca)

    return ca_certificate.decode("utf-8")
  except NotFoundException as e:
    return str(e), 404

def get_chain(ca):
  try:
    ca_certificate, _ = _load_ca(ca)

    if current_app.secretmanager.exists(parent_ca_filename, path=ca):
      parent = current_app.secretmanager.read_string(parent_ca_filename, path=ca)
    else:
      parent = None

    return _construct_ca_chain(asymmetric.load_certificate(ca_certificate), parent)
  except NotFoundException as e:
    return str(e), 404

def root(body, ttl=None):
  # Extract parameters
  name = body["name"]
  bit_size = int(body["size"])

  # Check if the private key for the new CA already exists
  if current_app.secretmanager.exists(private_key_filename, path=name):
    return f"CA {name} already exist", 400

  try:
    # Generate and save the key and certificate for the root CA
    root_ca_public_key, root_ca_private_key = asymmetric.generate_pair(encryption_schema, bit_size=bit_size)
    current_app.secretmanager.write_bytes(private_key_filename, asymmetric.dump_private_key(root_ca_private_key, None), path=name)

    # Create the self-signed certificate
    builder = CertificateBuilder(
        _construct_subject(body),
        root_ca_public_key
    )
    builder.self_signed = True
    builder.ca = True
    builder.end_date = _calc_enddate(ttl, current_app.config["CA_MAX_TTL"], current_app.config["CA_ROOT_TTL"])
    root_ca_certificate = builder.build(root_ca_private_key)

    current_app.certmanager.write_bytes(name, pem_armor_certificate(root_ca_certificate))

    return {
      "certificate": pem_armor_certificate(root_ca_certificate).decode('utf8'),
      "ca_chain": pem_armor_certificate(root_ca_certificate).decode('utf8')
    }, 201
  except NotFoundException as e:
    return str(e), 404
  except InvalidValueException as e:
    return str(e), 400


def intermediate(parent, body, ttl=None):
  """
  Create an intermediate CA

  An intermediate CA must be signed by another CA (the parent)

  :param parent:
    The parent CA used to sign the intermediate CA

  :param body:
    Dict containing the subject details of the new CA
  """
  # Check if the private key for the parent exists
  if not current_app.secretmanager.exists(private_key_filename, path=parent):
    return f"Parent CA {parent} doesn't exist", 400

  # Extract parameters
  name = body["name"]
  bit_size = int(body["size"])

  # Check if the private key for the new CA already exists
  if current_app.secretmanager.exists(private_key_filename, path=name):
    return f"CA {name} already exist", 400

  try:
    # Generate and save the key and certificate for the root CA
    intermediate_ca_public_key, intermediate_ca_private_key = asymmetric.generate_pair(encryption_schema, bit_size=bit_size)
    current_app.secretmanager.write_bytes(private_key_filename, asymmetric.dump_private_key(intermediate_ca_private_key, None), path=name)
    current_app.secretmanager.write_string(parent_ca_filename, parent, path=name)

    # Get the parent CA
    signing_ca_certificate, signing_ca_private_key = _load_ca(parent)

    # Create the certificate
    builder = CertificateBuilder(
        _construct_subject(body, parent=signing_ca_certificate),
        intermediate_ca_public_key
    )
    builder.ca = True
    builder.end_date = _calc_enddate(ttl, current_app.config["CA_MAX_TTL"], current_app.config["CA_INTERMEDIATE_TTL"])
    builder.issuer = asymmetric.load_certificate(signing_ca_certificate)
    intermediate_ca_certificate = builder.build(asymmetric.load_private_key(signing_ca_private_key, None))

    current_app.certmanager.write_bytes(name, pem_armor_certificate(intermediate_ca_certificate))

    return {
      "certificate": pem_armor_certificate(intermediate_ca_certificate).decode('utf8'),
      "ca_chain": _construct_ca_chain(intermediate_ca_certificate, parent)
    }, 201
  except NotFoundException as e:
    return str(e), 404
  except InvalidValueException as e:
    return str(e), 400
