from cryptography.hazmat.primitives.serialization import pkcs12
import string
from lxml import etree
from signxml import XMLSigner
from cryptography.hazmat.backends import default_backend
import re


class SAMLSigner():
    def __init__(self, data, template=None, password=None):
        self.key, self.cert = self.load_pkcs12(data, password)
        with open("templates/{0}.xml".format(template), 'r') as infile:
            self.saml_template = infile.read()

    def load_pkcs12(self, data, password):
        cert = pkcs12.load_key_and_certificates(data, password, default_backend())
        return cert[0], cert[1]

    def sign_XML(self, params, id_attribute, algorithm, digest):
        saml_string = string.Template(self.saml_template).substitute(params)
        data = etree.fromstring(saml_string)

        signed_xml = XMLSigner(c14n_algorithm="http://www.w3.org/2001/10/xml-exc-c14n#", signature_algorithm=algorithm, digest_algorithm=digest).sign(data, key=self.key, cert=[self.cert], reference_uri=params.get('AssertionID'), id_attribute=id_attribute)
        signed_saml_string = etree.tostring(signed_xml).replace(b'\n', b'')
        signed_saml_string = re.sub(b'-----(BEGIN|END) CERTIFICATE-----', b'', signed_saml_string)
        return signed_saml_string
