#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# base import {{
import os
from os.path import expanduser
import sys
import argparse
import yaml
import re
import logging
import inspect
# }}

import imaplib
import email
from email.header import decode_header
import base64
import gzip
import zipfile
from datetime import datetime, timedelta
import xmltodict
import textwrap

# !!!
# for gmail you need enable access for "less secure apps"
# https://support.google.com/a/answer/6260879?hl=en
# !!!

# base {{
# default vars
scriptName = os.path.basename(sys.argv[0]).split('.')[0]
homeDir = expanduser("~")
defaultConfigFiles = [
    '/etc/' + scriptName + '/config.yaml',
    homeDir + '/.' + scriptName + '.yaml',
    './.config.yaml',
]
cfg = {
    'logFile': '/var/log/' + scriptName + '/' + scriptName + '.log',
    'logFile': 'stdout',
    'logLevel': 'info',
    "email": {
        "address": "user@example.com",
        "password": "secret",
        "server": "imap.gmail.com",
    },
    "dmarc": {
        "reportsDir": "./tmp/reports",
    },
    "searchLimitDays": 30,
    "inboxSelect": "INBOX",
    "skipDownloadReports": False,
}

# parse args
parser = argparse.ArgumentParser( description = '''
default config files: %s

''' % ', '.join(defaultConfigFiles),
formatter_class=argparse.RawTextHelpFormatter
)
parser.add_argument(
    '-c',
    '--config',
    help = 'path to config file',
)
args = parser.parse_args()
argConfigFile = args.config

# get settings
if argConfigFile:
    if os.path.isfile(argConfigFile):
        try:
            with open(argConfigFile, 'r') as ymlfile:
                cfg.update(yaml.load(ymlfile,Loader=yaml.Loader))
        except Exception as e:
            logging.error("main: failed load config file: '%s', error: '%s'", argConfigFile, e)
            exit(1)
else:
    for configFile in defaultConfigFiles:
        if os.path.isfile(configFile):
            try:
                with open(configFile, 'r') as ymlfile:
                    try:
                        cfg.update(yaml.load(ymlfile,Loader=yaml.Loader))
                    except Exception as e:
                        logging.warning("main: skipping load load config file: '%s', error '%s'", configFile, e)
                        continue
            except:
                continue

# fix logDir
cfg['logDir'] = os.path.dirname(cfg['logFile'])
if cfg['logDir'] == '':
    cfg['logDir'] = '.'
# }}

# defs
def process_record(record, sources, domains):
    """
    Function that processes individual records within a DMARC report file.

    Required arguments:
        record: A dictionary version of the "record" tree from the DMARC report.
        sources: A dictionary containing all source IP addresses found so far.
        domains: A dictionary containing all source domains found so far.

    Returns:
        sources: Updated version of the argument which contains the processed IP address.
        domains: Updated version of the argument which contains the processed domain.
    """

    defName = inspect.stack()[0][3]

    # Fetch needed info from the report data.
    source_ip = record['row']['source_ip']
    source_domain = record['identifiers']['header_from']
    count = int(record['row']['count'])
    policy_evaluated_dkim = record['row']['policy_evaluated']['dkim']
    policy_evaluated_spf = record['row']['policy_evaluated']['spf']

    spf_auth_results = record['auth_results'].get('spf', None)
    if isinstance(spf_auth_results, dict):
        spf_auth_results = [spf_auth_results]

    dkim_auth_results = record['auth_results'].get('dkim', None)
    if isinstance(dkim_auth_results, dict):
        dkim_auth_results = [dkim_auth_results]

    # DKIM fail and SPF fail required to fail DMARC
    if policy_evaluated_dkim == 'fail' or policy_evaluated_spf == 'fail':
        policy_evaluated_status = 'fail'
    else:
        policy_evaluated_status = 'pass'

    emptyStructure = {
        'policy_evaluated': {
            'dkim': {
                'fail': 0,
                'pass': 0,
            },
            'spf': {
                'fail': 0,
                'pass': 0,
            },
        },
        'spf_auth': {
            'fail': {},
            'pass': {},
        },
        'dkim_auth': {
            'fail': {},
            'pass': {},
        },
    }
    # Set up the count dictionary if not existing for this IP
    if source_ip not in sources:
        sources[source_ip] = emptyStructure

    # Set up the count dictionary if not existing for this domain
    if source_domain not in domains:
        domains[source_domain] = emptyStructure

    # policy_evaluated
    if policy_evaluated_dkim == 'pass':
        domains[source_domain]['policy_evaluated']['dkim']['pass'] += count
    else:
        domains[source_domain]['policy_evaluated']['dkim']['fail'] += count
    if policy_evaluated_spf == 'pass':
        domains[source_domain]['policy_evaluated']['spf']['pass'] += count
    else:
        domains[source_domain]['policy_evaluated']['spf']['fail'] += count


    # spf info
    if spf_auth_results:
        for spf_auth in spf_auth_results:
            spf_auth_domain = spf_auth.get('domain', 'unknown')
            spf_auth_result = spf_auth.get('result', 'unknown')
            spf_auth_line = spf_auth_domain +":"+ spf_auth_result
            if spf_auth_result == 'pass':
                if spf_auth_line in domains[source_domain]['spf_auth']['pass']:
                    domains[source_domain]['spf_auth']['pass'][spf_auth_line] += 1
                else:
                    domains[source_domain]['spf_auth']['pass'][spf_auth_line] = 1
                if spf_auth_line in sources[source_ip]['spf_auth']['pass']:
                    sources[source_ip]['spf_auth']['pass'][spf_auth_line] += 1
                else:
                    sources[source_ip]['spf_auth']['pass'][spf_auth_line] = 1
            else:
                if spf_auth_line in domains[source_domain]['spf_auth']['fail']:
                    domains[source_domain]['spf_auth']['fail'][spf_auth_line] += 1
                else:
                    domains[source_domain]['spf_auth']['fail'][spf_auth_line] = 1
                if spf_auth_line in sources[source_ip]['spf_auth']['fail']:
                    sources[source_ip]['spf_auth']['fail'][spf_auth_line] += 1
                else:
                    sources[source_ip]['spf_auth']['fail'][spf_auth_line] = 1

    # dkim info
    if dkim_auth_results:
        for dkim_auth in dkim_auth_results:
            dkim_auth_domain = dkim_auth.get('domain', 'unknown')
            dkim_auth_result = dkim_auth.get('result', 'unknown')
            dkim_auth_selector = dkim_auth.get('selector', 'unknown')
            dkim_auth_line = dkim_auth_domain +":"+ dkim_auth_result +":"+ dkim_auth_selector
            if dkim_auth_result == 'pass':
                if dkim_auth_line in domains[source_domain]['dkim_auth']['pass']:
                    domains[source_domain]['dkim_auth']['pass'][dkim_auth_line] += 1
                else:
                    domains[source_domain]['dkim_auth']['pass'][dkim_auth_line] = 1
                if dkim_auth_line in sources[source_ip]['dkim_auth']['pass']:
                    sources[source_ip]['dkim_auth']['pass'][dkim_auth_line] += 1
                else:
                    sources[source_ip]['dkim_auth']['pass'][dkim_auth_line] = 1
            else:
                if dkim_auth_line in domains[source_domain]['dkim_auth']['fail']:
                    domains[source_domain]['dkim_auth']['fail'][dkim_auth_line] += 1
                else:
                    domains[source_domain]['dkim_auth']['fail'][dkim_auth_line] = 1
                if dkim_auth_line in sources[source_ip]['dkim_auth']['fail']:
                    sources[source_ip]['dkim_auth']['fail'][dkim_auth_line] += 1
                else:
                    sources[source_ip]['dkim_auth']['fail'][dkim_auth_line] = 1

    # Return our results.
    return sources, domains

def downloadReports():
    defName = inspect.stack()[0][3]

    # connect to server
    mail = imaplib.IMAP4_SSL(cfg['email']['server'])
    mail.login(cfg['email']['address'], cfg['email']['password'])

    # get search limit days time
    if cfg['searchLimitDays']:
        monthAgo = datetime.now() - timedelta(days=cfg['searchLimitDays'])
        # format for imap server
        searchDate = monthAgo.strftime("%d-%b-%Y")

    # chouse inbox
    mail.select(cfg['inboxSelect'], readonly=True)

    # search emails
    if cfg['searchLimitDays']:
        status, messages = mail.search(None, f'SINCE "{searchDate}"')
    else:
        status, messages = mail.search(None, "ALL")

    # check search status
    if status != "OK":
        logging.critical("%s: failed mail search, status='%s'" % (defName,status))
        exit(1)

    message_ids = messages[0].split()

    # create dir for reports
    try:
        os.makedirs(cfg['dmarc']['reportsDir'])
    except OSError:
        if not os.path.isdir(cfg['dmarc']['reportsDir']):
            raise

    for msg_id in message_ids:
        # get mails on id
        _, msg_data = mail.fetch(msg_id, "(RFC822)")
        raw_email = msg_data[0][1]

        # convert in message object
        msg = email.message_from_bytes(raw_email)

        # get subject
        subject, encoding = decode_header(msg["Subject"])[0]
        if isinstance(subject, bytes):
            subject = subject.decode(encoding or "utf-8")
        subject = re.sub(r'[\n\r]', '', subject)

        # get reportId from subject
        match = re.search(r'^.*Report-ID(.*)$', subject, re.MULTILINE | re.IGNORECASE)
        if match:
            reportID = match.group(1)
            reportID = re.sub(r'[\s:\{\}<>]', '', reportID)
            if reportID == '':
                logging.warning("%s: Report-ID is empty, subject='%s'" % (defName,subject))
                continue
            else:
                logging.info("%s: Report-ID='%s', subject=='%s'" % (defName,reportID,subject))
        else:
            logging.warning("%s: Report-ID not found, skipped. subject=='%s'" % (defName,subject))
            continue

        # check attache exists
        savedAttachment = False
        for part in msg.walk():
            if part.get_content_disposition() == "attachment":
                # get attache data
                if part.get_content_maintype() == 'multipart' or part.get('Content-Disposition') is None:
                    continue
                filename = part.get_filename()
                if not filename:
                    logging.warning(f"{defName}: failed get filename for email with msg_id='{msg_id}'")
                    continue
                data = part.get_payload(decode=True)

                # check file report exists
                filePath = cfg['dmarc']['reportsDir']+'/'+reportID+'_'+filename
                if os.path.exists(filePath) and os.path.getsize(filePath) > 0:
                    logging.info(f"{defName}: Attachment '{filePath}' for email msg_id={msg_id} is already exists, skipped")
                    savedAttachment = True
                else:
                    # save attachment in file
                    with open(filePath, "wb") as f:
                        f.write(data)
                    logging.info(f"Attachment '{filename}' saved from email with ID {msg_id}")
                    savedAttachment = True

        if not savedAttachment:
            logging.warning(f"Attachment not found for ID {msg_id}")

        logging.info("Subject: %s", subject)
        logging.info("=" * 50)

    # close mail connect
    mail.logout()

def generateReports():
    defName = inspect.stack()[0][3]

    providers = {}
    sources = {}
    domains = {}
    directory=cfg['dmarc']['reportsDir']

    for file in os.listdir(directory):
        filename = f'{directory}/{file}'
        # If it's a regular .gz archive
        match = re.search(r'^.*\.xml\.gz$', file, re.MULTILINE | re.IGNORECASE)
        if match:
            # gzip doesn't provide a filename, so split out one
            outfile = filename.split('.gz')[0]
            # Open the archive file handler
            with gzip.open(filename, 'rb') as f_in:
                # Open the output file handler
                with open(outfile, 'wb') as f_out:
                    # Write to the output file from the archive file.
                    f_out.write(f_in.read())
        # If it's a regular .zip archive
        match = re.search(r'^.*\.zip$', file, re.MULTILINE | re.IGNORECASE)
        if match:
            # gzip doesn't provide a filename, so split out one
            outfile = filename.split('.zip')[0]
            with zipfile.ZipFile(filename, 'r') as zipRef:
                # get list files on archive
                zipFileList = zipRef.namelist()
                # extract only if archive have one file
                zipFileListLen = len(zipFileList)
                if zipFileListLen == 1:
                    fileInZip = zipFileList[0]
                    fileToExtract = outfile + '.xml'
                    with zipRef.open(fileInZip) as fileInZip, open(os.path.join(fileToExtract), 'wb') as extractedFile:
                        extractedFile.write(fileInZip.read())
                else:
                    logging.warning(f"{defName}: bad zip archive='{filename}', error: too many files, count='{zipFileListLen}'")
                    continue

    # Refresh our file list.
    for file in os.listdir(directory):
        # Grab the actual XML files, not the compressed files.
        if '.xml' in file and '.gz' not in file and '.zip' not in file:
            with open(f'{directory}/{file}', 'r', encoding='utf8') as f:
                content = f.read()

            # Convert XML to Dictionary. Data is within the 'feedback' header.
            data = xmltodict.parse(content)['feedback']
            # Fetch provider here since it's not in the record.
            provider = data['report_metadata']['org_name']

            # We only increment provider by 1, as this is just 1 report w/ potentially multiple records.
            if provider in providers:
                providers[provider] += 1
            else:
                providers[provider] = 1

            # Store the record(s) in a variable, so we can check if there's multiple.
            records = data['record']

            # List means multiple reports.
            if type(records) == list:
                for record in records:
                    sources, domains = process_record(record, sources, domains)
            else:
                sources, domains = process_record(records, sources, domains)

    # Output our summary.
    print('\nReports evaluated:')
    for provider in sorted(providers.keys()):
        print(f'{provider}: {providers[provider]}')

    print('\nMessages per Source IP:')
    for source in sorted(sources.keys()):
        data = sources[source]
        print(f"    {source}")
        print(textwrap.indent(yaml.dump(data, indent=4), "        "))

    print('\nMessages per Source Domain:')
    for domain in sorted(domains.keys()):
        data = domains[domain]
        print(f"    {domain}")
        print(textwrap.indent(yaml.dump(data, indent=4), "        "))

if __name__ == "__main__":
    # basic config {{
    for dirPath in [
        cfg['logDir'],
    ]:
        try:
            os.makedirs(dirPath)
        except OSError:
            if not os.path.isdir(dirPath):
                raise

    # choice loglevel
    if re.match(r"^(warn|warning)$", cfg['logLevel'], re.IGNORECASE):
        logLevel = logging.WARNING
    elif re.match(r"^debug$", cfg['logLevel'], re.IGNORECASE):
        logLevel = logging.DEBUG
    else:
        logging.getLogger("urllib3").setLevel(logging.WARNING)
        logging.getLogger("requests").setLevel(logging.WARNING)
        logLevel = logging.INFO

    if cfg['logFile'] == 'stdout':
        logging.basicConfig(
            level       = logLevel,
            format      = '%(asctime)s\t%(name)s\t%(levelname)s\t%(message)s',
            datefmt     = '%Y-%m-%dT%H:%M:%S',
        )
    else:
        logging.basicConfig(
            filename    = cfg['logFile'],
            level       = logLevel,
            format      = '%(asctime)s\t%(name)s\t%(levelname)s\t%(message)s',
            datefmt     = '%Y-%m-%dT%H:%M:%S',
        )
    # }}

    defName = "main"

    if not cfg['skipDownloadReports']:
        downloadReports()
    generateReports()
