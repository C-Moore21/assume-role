from botocore.exceptions import ClientError
from dateutil.tz import tzutc
from jinja2 import Template
from subprocess import Popen, PIPE, STDOUT

import argparse
import boto3
import datetime
import getpass
import pkg_resources
import os
import json
import pathlib


AWS_PROFILE = 'default'
AWS_REGION = None
AWS_DEFAULT_REGION = 'us-east-1'
AWS_SESSION_TOKEN = None
AWS_CONFIG_FILE = '{home}/.aws/config'.format(home=pathlib.Path.home())
AWS_CREDIENTIALS_FILE = '{home}/.aws/credentials'.format(home=pathlib.Path.home())
AWS_ACCOUNTS_FILE = '{home}/.aws/accounts'.format(home=pathlib.Path.home())
AWS_SESSION_FILE = '{home}/.aws/session'.format(home=pathlib.Path.home())
AWS_SESSION_TOKEN_TIMEOUT = 3600
aws_session_data = {
    "AWS_REGION": None,
    "AWS_DEFAULT_REGION": None,
    "AWS_ACCESS_KEY_ID": None,
    "AWS_SECRET_ACCESS_KEY": None,
    "AWS_SESSION_TOKEN": None,
    "AWS_ACCOUNT_ID": None,
    "AWS_ACCOUNT_NAME": None,
    "AWS_STS_SESSION_ACCESS_KEY_ID": None,
    "AWS_STS_SESSION_SECRET_ACCESS_KEY": None,
    "AWS_STS_SESSION_TOKEN": None,
    "AWS_STS_SESSION_EXPIRATION_DATETIME": None
}

def parse_arguments():
    description = "A CLI tool making it easy to assume IAM roles through an AWS Bastion account."
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument('account_name', help='The AWS account name from ~/.aws/accounts.')
    parser.add_argument('iam_role', help='The IAM role to assume on the account.')
    parser.add_argument('mfa_token', help='The MFA token.', nargs='?', default=None)
    parser.add_argument('-q', '--quiet', action='store_false', help='.')
    parser.add_argument('-v', '--version', action='version',
        version=pkg_resources.get_distribution('assume-role').version)
    args = parser.parse_args()
    return args.account_name, args.iam_role, args.mfa_token


def main(args=None):
    account_name, iam_role, mfa_token = parse_arguments()
    
    # attempt to use existing sts session.
    datetime_now = datetime.datetime.now(tzutc())
    if not mfa_token:
        if has_current_sts_session_expired(datetime_now):
            print('the mfa token has expired')
            mfa_token = get_for_mfa_token_from_user()

    # create a new sts session.
    session = boto3.Session()
    account_id = get_aws_account_id(account_name)
    sts_session_credentials = get_sts_session_credentials(
        session,
        account_name,
        account_id,
        iam_role,
        datetime_now,
        mfa_token=mfa_token
    )
    update_aws_session_data(
        session.region_name,
        AWS_DEFAULT_REGION,
        session.get_credentials().access_key,
        session.get_credentials().secret_key,
        session.get_credentials().token,
        account_id,
        account_name,
        sts_session_credentials['AccessKeyId'],
        sts_session_credentials['SecretAccessKey'],
        sts_session_credentials['SessionToken'],
        sts_session_credentials['Expiration'] 
    )
    write_aws_session_data()


def get_current_aws_sts_session_data():
    try:
        return aws_session_data.update(
            {
                "AWS_REGION": os.environ['AWS_REGION'],
                "AWS_DEFAULT_REGION": os.environ['AWS_DEFAULT_REGION'],
                "AWS_ACCESS_KEY_ID": os.environ['AWS_ACCESS_KEY_ID'],
                "AWS_SECRET_ACCESS_KEY": os.environ['AWS_SECRET_ACCESS_KEY'],
                "AWS_SESSION_TOKEN": os.environ['AWS_SESSION_TOKEN'],
                "AWS_ACCOUNT_ID": os.environ['AWS_ACCOUNT_ID'],
                "AWS_ACCOUNT_NAME": os.environ['AWS_ACCOUNT_NAME'],
                "AWS_STS_SESSION_ACCESS_KEY_ID": os.environ['AWS_STS_SESSION_ACCESS_KEY_ID'],
                "AWS_STS_SESSION_SECRET_ACCESS_KEY": os.environ['AWS_STS_SESSION_SECRET_ACCESS_KEY'],
                "AWS_STS_SESSION_TOKEN": os.environ['AWS_STS_SESSION_TOKEN'],
                "AWS_STS_SESSION_EXPIRATION_DATETIME": os.environ['AWS_STS_SESSION_EXPIRATION_DATETIME']
            }
        )
    except KeyError as ke:
        return None


def has_current_sts_session_expired(datetime_now):
    try:
        print('now: ' + datetime_now)
        print('expire: ' + eval(os.environ["AWS_STS_SESSION_EXPIRATION_DATETIME"]))
        return datetime_now > eval(os.environ["AWS_STS_SESSION_EXPIRATION_DATETIME"])
    except:
        return True


def get_for_mfa_token_from_user():
    return getpass.getpass(prompt='MFA Token: ')


def get_aws_account_id(account_name):
    if not os.path.isfile(AWS_ACCOUNTS_FILE):
        print("The {path} file must exist.".format(path=AWS_ACCOUNTS_FILE))
        exit(1)
    with open(AWS_ACCOUNTS_FILE, 'r') as file:
        acount_name_to_account_id = json.load(file)
        if account_name not in acount_name_to_account_id:
            print("Could not find '{name}' account name so using 'default' instead.'".format(name=account_name))
        return acount_name_to_account_id.get(account_name, 'default')


def get_mfa_devices(session):
    iam = session.client('iam')
    mfa_devices = []
    try:
        first_idx = 0
        mfa_devices = iam.list_mfa_devices()['MFADevices']
    except KeyError as ke:
        print('Bastion user does not have a MFA device enabled.')
    return mfa_devices


def get_role_arn(account_id, role):
    return 'arn:aws:iam::{account_id}:role/{role}'.format(
        account_id=account_id,
        role=role
    )


def get_sts_session_credentials(session, account_name, account_id, role,
    datetime, mfa_token=None):
    try:
        sts = session.client('sts')
        if mfa_token:
            print('assume role with new mfa code.')
            for mfa_device in get_mfa_devices(session):
                return sts.assume_role(
                    RoleArn=get_role_arn(account_id, role),
                    RoleSessionName=account_name,
                    DurationSeconds=AWS_SESSION_TOKEN_TIMEOUT,
                    SerialNumber=mfa_device['SerialNumber'],
                    TokenCode=mfa_token
                )['Credentials']
        else:
            print('assume role with existing sts token.')
            return sts.assume_role(
                RoleArn=get_role_arn(account_id, role),
                RoleSessionName=account_name,
                DurationSeconds=AWS_SESSION_TOKEN_TIMEOUT
            )['Credentials']
    except ClientError as ce:
        if ce.response['Error']['Code'] == 'AccessDenied':
            print(ce.response['Error']['Message'])
            exit(1)
        else:
            print("Unexpected error: {client_error}".format(client_error=ce))
            exit(1)


def update_aws_session_data(aws_region, aws_default_region, aws_access_key_id,
    aws_secret_access_key, aws_session_token, aws_account_id, aws_account_name,
    aws_sts_session_access_key_id, aws_sts_session_secret_access_key,
    aws_sts_session_token, aws_sts_session_expiration_datetime):
    
    os.chmod(AWS_SESSION_FILE, 0o700)
    # fill out default
    aws_session_data.update(
        {
            "AWS_REGION": aws_region,
            "AWS_DEFAULT_REGION": aws_default_region,
            "AWS_ACCESS_KEY_ID": aws_access_key_id,
            "AWS_SECRET_ACCESS_KEY": aws_secret_access_key,
            "AWS_SESSION_TOKEN": aws_session_token,
            "AWS_ACCOUNT_ID": aws_account_id,
            "AWS_ACCOUNT_NAME": aws_account_name,
            "AWS_STS_SESSION_ACCESS_KEY_ID": aws_sts_session_access_key_id,
            "AWS_STS_SESSION_SECRET_ACCESS_KEY": aws_sts_session_secret_access_key,
            "AWS_STS_SESSION_TOKEN": aws_sts_session_token,
            "AWS_STS_SESSION_EXPIRATION_DATETIME": str(repr(aws_sts_session_expiration_datetime))
        }
    )


def write_aws_session_data():
    session_file_lines = []
    for key in aws_session_data.keys():
        session_file_lines.append(
            'export {envar}="{value}"'.format(
                envar=key,
                value=aws_session_data[key]
            )
        )
    formatted_aws_session_data = '\n'.join(session_file_lines)
    print(formatted_aws_session_data)

    with open(AWS_SESSION_FILE, 'w'):
        pass  # clear file
    with open(AWS_SESSION_FILE, 'a') as f:
        f.write(formatted_aws_session_data)

if __name__ == '__main__':
    main()
