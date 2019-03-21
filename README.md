# ADFSpoof

A python tool to forge AD FS security tokens.

Created by Doug Bienstock [(@doughsec)](https://twitter.com/doughsec) while at Mandiant FireEye.

## Detailed Description

ADFSpoof has two main functions:
1. Given the EncryptedPFX blob from the AD FS configuration database and DKM decryption key from Active Directory, produce a usable key/cert pair for token signing.
2. Given a signing key, produce a signed security token that can be used to access a federated application.

This tool is meant to be used in conjunction with ADFSDump. ADFSDump runs on an AD FS server and outputs important information that you will need to use ADFSpoof.

If you are confused by the above, you might want to read up on AD FS first. For more information on AD FS spoofing I will post a link to my TROOPERS 19 talk and slides when they are released.

## Installation

ADFSpoof is written in Python 3.

ADFSpoof requires the installation of a custom fork of the Python Cryptography package, available [here](https://github.com/dmb2168/cryptography). Microsoft did not exactly follow the RFC for Key Deriviation :wink:, so a fork of the package was needed.

All other requirements are captured in the repo's requirements.txt.

`pip install -r requirements.txt`

## Usage

```
usage: ADFSpoof.py [-h] (-b BLOB BLOB | -c CERT) [-p PASSWORD] [-v VERBOSE]
                   [--assertionid ASSERTIONID] [--responseid RESPONSEID]
                   [-s SERVER] [-a ALGORITHM] [-d DIGEST] [-o OUTPUT]
                   {o365,dropbox,saml2,dump} ...

optional arguments:
  -h, --help            show this help message and exit
  -b BLOB BLOB, --blob BLOB BLOB
                        Encrypted PFX blob and decryption key
  -c CERT, --cert CERT  AD FS Signing Certificate
  -p PASSWORD, --password PASSWORD
                        AD FS Signing Certificate Password
  -v VERBOSE, --verbose VERBOSE
                        Verbose Output
  --assertionid ASSERTIONID
                        AssertionID string. Defaults to a random string
  --responseid RESPONSEID
                        The Response ID. Defaults to random string
  -s SERVER, --server SERVER
                        Identifier for the federation service. Usually the
                        fqdn of the server. e.g. sts.example.com DO NOT
                        include HTTPS://
  -a ALGORITHM, --algorithm ALGORITHM
                        SAML signing algorithm to use
  -d DIGEST, --digest DIGEST
                        SAML digest algorithm to use
  -o OUTPUT, --output OUTPUT
                        Write generated token to the supplied filepath

modules:
  loaded modules

  {o365,dropbox,saml2,dump}
                        additional help
```
### Cryptographic Material

All ADFSpoof functionality requires cryptographic material for the AD FS signing key. This can be supplied in one of two ways:

* `-b BLOB BLOB`: Supply the EncryptedPFX binary blob (base64 decode what is pulled out of the configuration database) and the DKM key from Active directory. Order matters!
* `-c CERT`: Provide a PKCS12-formatted file for the signing key and certificate. If it is password protected supply a password with `-p`. The overall file password and private key password must be the same.


### Global Options

* `-s SERVER`: The AD FS service identifier. Required when using any module that generates a security token. This goes into the security token to let the federated application know who generated it.
* `-o FILEPATH`: Outputs the generated token to disk instead of printing it.
* `--assertionid` and `--responseid`: If you wish to supply custom attribute values for SAML AssertionID and ResponseID. Defaults to random strings.
* `-d DIGEST`: Set the MAC digest algorithm. Defaults to SHA256.
* `-a ALGORITHM`: Set the signature algorithm. Defaults to RSA-SHA256.


### Command Modules

ADFSpoof is built modularly with easy expansion in mind. Currently, it comes preloaded with four command modules that support different functionality.

Each module encapsulates the SAML attributes and values necessary to generate a valid security token for a specific token type or federated application. *Note that for the applications specific modules, the template represents the generic installation. Customization may be required for organizations that have messed with the defaults.*

#### o365

Generates a forged security token to access Microsoft Office 365. This is a SAML 1.1 token.

* `--upn UPN`: The universal principal name of the user to generate a token for. Get this from AD.
* `--objectguid`: The Object GUID of the user to generate a token for. Get this from AD. Include the curly braces.

#### Dropbox

Generats a forged security token to access Dropbox. This is a SAML 2.0 token.

* `--email EMAIL`: The email address of the user to generate a token for.
* `--accountname ACCOUNT`: The SamAccountName of the user to generate a token for.

#### SAML2

A command that encapsulates generating a generic SAML 2.0 security token. Use this module to generate security tokens for arbitrary federated applications that are using SAML 2.0. By reading the data returned by ADFSDump you should be able to generate a valid token for just about any federated application using this module.

* `--endpoint ENDPOINT`: The recipient of the seucrity token. This should be a full URL.
* `--nameidformat URN`: The value for the 'Format' attribute of the NameIdentifier tag. This should be a URN.
* `--nameid NAMEID`: The NameIdentifier attribute value.
* `--rpidentifier IDENTIFIER`: The Identifier of the relying party that is receiving the token.
* `--assertions ASSERTIONS`: The assertions that the relying party is expecting. Use the claim rules output by ADFSDump to ascertain this. Should be a single-line (do not include newlines) XML string.
* `--config FILEPATH`: A filepath to a JSON file containing the above arguments. Optional - use this if you don't want to supply everything over the command line.

#### Dump

Helper command that will take the supplied EncryptedPFX blob and DKM key from `-b`, decrypt the blob, and output the PFX file to disk. Use this to save the PFX for later.

`--path PATH`: The filepath to save the generated PFX.

### Examples

#### Decrypt the EncryptedPFX and write to disk
`python ADFSpoof.py -b EncryptedPfx.bin DKMkey.bin dump`

#### Generate a security token for Office365

`python ADFSpoof.py -b EncryptedPfx.bin DkmKey.bin -s sts.doughcorp.com o365 --upn robin@doughcorp.co --objectguid {1C1D4BA4-B513-XXX-XXX-3308B907D759}`

#### Generate a SAML 2.0 token for some app

`python ADFSpoof.py -b EncryptedPfx.bin DkmKey.bin -s sts.doughcorp.com saml2 --endpoint https://my.app.com/access/saml --nameidformat urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress --nameid robin@doughcorp.com --rpidentifier myapp --assertions <Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"><AttributeValue>robin@doughcorp.com</AttributeValue></Attribute>`

### Reading Issuance Authorization Rules

More coming soon! As a tl;dr for SAML 2.0 each issuance rule (with the exception of the nameid rule) is going to be translated into a SAML assertion. SAML assertions are <Attribute><AttributeValue></AttributeValue><Attribute> tags. The Attribute tag must have an attribute called "Name" that value of which is the claim type. The claim value goes inside the <AttributeValue> tags.
  
  There is a little more nuance which I hope to discuss in a wiki page soon, but that is the basic idea. Relying Parties may have "StrongAuth" rules and MFA requirements, but usually we don't care about those.



