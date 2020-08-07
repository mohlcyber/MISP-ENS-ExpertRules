#!/usr/bin/env python3
# Written by mohlcyber v.0.1 03/07/2020

import os
import time
import sys
import requests
import json
import xml.etree.ElementTree as ET
import base64
import re
import logging

from pymisp import ExpandedPyMISP

requests.packages.urllib3.disable_warnings()

EPO_URL = 'https://1.1.1.1'
EPO_PORT = '8443'
EPO_USERNAME = 'admin'
EPO_PASSWORD = 'pass'
EPO_POLICY_NAME = 'Expert Rule Policy'
EPO_SIGNATURE_ID = '20000'

MISP_URL = 'https://2.2.2.2/'
MISP_KEY = 'api key'
MISP_VERIFY = False
MISP_TAG = 'McAfee: Update ENS Expert Rules'

HASH_FILE = 'exports/misp_hashes.txt'
MAXIMUM = 10

loglevel = 'INFO'
logger = logging.getLogger('logs')
logger.setLevel(loglevel)

consoleHandler = logging.StreamHandler()
consoleHandler.setLevel(loglevel)

logger.addHandler(consoleHandler)

formatter = logging.Formatter("%(asctime)s;%(levelname)s;%(message)s")
consoleHandler.setFormatter(formatter)


class MISP():
    def __init__(self):
        self.misp = ExpandedPyMISP(MISP_URL, MISP_KEY, MISP_VERIFY)
        self.misp_hashes = []

    def query(self):
        try:
            events = self.misp.search(tags=MISP_TAG)
            if events:
                for event in events:
                    eventid = str(event['Event']['id'])
                    for attributes in event['Event']['Attribute']:
                        if attributes['type'] == 'md5':
                            self.misp_hashes.append(attributes['value'])

                    for objects in event['Event']['Object']:
                        for attributes in objects['Attribute']:
                            if attributes['type'] == 'md5':
                                self.misp_hashes.append(attributes['value'])

                    self.misp.untag(event['Event']['uuid'], MISP_TAG)

                logger.info('STATUS: Found {0} Hash in MISP Events that use tag {1}.'.format(str(len(self.misp_hashes)), MISP_TAG))
                self.write_to_file()
                return True
            else:
                return False

        except Exception as error:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            logger.info('ERROR: Error in {location}.{funct_name}() - line {line_no} : {error}'
                  .format(location=__name__, funct_name=sys._getframe().f_code.co_name, line_no=exc_tb.tb_lineno,
                          error=str(error)))

    def write_to_file(self):
        if os.path.exists(HASH_FILE):
            tmp_dict = []
            hashes = open(HASH_FILE, 'r')
            hashes_read = hashes.read()
            for line in hashes_read.split('\n'):
                tmp_dict.append(line)

            for hash in self.misp_hashes:
                if hash not in tmp_dict:
                    tmp_dict.append(hash)

            count = len(tmp_dict)
            if count > MAXIMUM:
                logger.info('ATTENTION: Maximum amount of hashes reached. Removing oldest.')
                diff = count - MAXIMUM
                s = slice(diff, None)
                tmp_dict = tmp_dict[s]

            os.remove(HASH_FILE)
            hashes = open(HASH_FILE, 'w')

            if count > MAXIMUM:
                count = MAXIMUM
            for hash in tmp_dict:
                if count > 1:
                    hashes.write(hash + '\n')
                else:
                    hashes.write(hash)
                count -= 1
            hashes.close()
        else:
            hashes = open(HASH_FILE, 'w')
            count = len(self.misp_hashes)

            if count > MAXIMUM:
                logger.info('ATTENTION: Maximum amount of hashes reached. Removing oldest.')
                diff = count - MAXIMUM
                s = slice(diff, None)
                self.misp_hashes = self.misp_hashes[s]

            if count > MAXIMUM:
                count = MAXIMUM
            for hash in self.misp_hashes:
                if count > 1:
                    hashes.write(hash + '\n')
                else:
                    hashes.write(hash)
                count -= 1
            hashes.close()

class EPO():
    def __init__(self):
        self.epo_url = EPO_URL
        self.epo_port = EPO_PORT
        self.epo_verify = False

        self.epo_user = EPO_USERNAME
        self.epo_pw = EPO_PASSWORD

        self.session = requests.Session()
        self.policy = EPO_POLICY_NAME

        self.expert_tmp = open('expert_tmp.txt', 'r').read()
        self.expert_rule = ''

    def request(self, option, **kwargs):
        try:
            kwargs.setdefault('auth', (self.epo_user, self.epo_pw))
            kwargs.setdefault('verify', self.epo_verify)
            kwargs.setdefault('params', {})
            kwargs['params'][':output'] = 'json'

            url = '{}:{}/remote/{}'.format(self.epo_url, self.epo_port, option)

            if kwargs.get('data') or kwargs.get('json') or kwargs.get('files'):
                res = self.session.post(url, **kwargs)
            else:
                res = self.session.get(url, **kwargs)

            return res.status_code, res

        except Exception as error:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            logger.info('ERROR: Error in {location}.{funct_name}() - line {line_no} : {error}'
                  .format(location=__name__, funct_name=sys._getframe().f_code.co_name, line_no=exc_tb.tb_lineno,
                          error=str(error)))

    def prep_xml(self):
        org_xml = open('exports/policy_old.xml', 'r')
        hashes = open(HASH_FILE, 'r').read()
        tmp_hashes = []
        for line in hashes.split('\n'):
            tmp_hashes.append(line)

        tree_org = ET.parse(org_xml)
        root_org = tree_org.getroot()

        tree_mod = ET.ElementTree()
        root_mod = ET.Element('epo:EPOPolicySchema')
        root_mod.attrib = {
            'xmlns:epo': 'mcafee-epo-policy',
            'xmlns:xsi': 'http://www.w3.org/2001/XMLSchema-instance'
        }

        for shema in root_org.iter('epo:EPOPolicySchema'):
            root_mod.append(shema)

        for info in root_org.iter('EPOPolicyVerInfo'):
            root_mod.append(info)

        for set in root_org.iter('EPOPolicySettings'):
            if EPO_POLICY_NAME in set.attrib['name']:

                if set.attrib['categoryid'] == 'EAM_BufferOverflow_Policies':
                    for setting in set.iter('Setting'):
                        if setting.attrib['name'] == 'SignatureID' and setting.attrib['value'] == EPO_SIGNATURE_ID:
                            for setting in set.iter('Setting'):
                                if 'SignatureContent' in setting.attrib['name']:
                                    # org_payload = setting.attrib['value']
                                    # enc_org_payload = (base64.b64decode(org_payload)).decode()

                                    for line in self.expert_tmp.split('\n'):
                                        md5_line = re.findall(r'.-v\s\x22', line)
                                        if len(md5_line) > 0:
                                            for hash in tmp_hashes:
                                                nline = re.sub(r'(HASH)', hash, line)
                                                self.expert_rule += nline + '\r\n'
                                        else:
                                            self.expert_rule += line + '\r\n'

                                    setting.attrib['value'] = base64.b64encode(self.expert_rule.encode()).decode()

                root_mod.append(set)

        for obj in root_org.iter('EPOPolicyObject'):
            if 'Expert Rule Test Policy' in obj.attrib['name']:
                root_mod.append(obj)

        tree_mod._setroot(root_mod)
        tree_mod.write('exports/policy_new.xml', encoding='utf-8', xml_declaration=True)


def main():
    misp = MISP()
    logger.debug('STATUS: Starting to query MISP for Events with tag {0}.'.format(str(MISP_TAG)))
    if misp.query() is False:
        logger.debug('SUCCESS: No MISP Events found with tag {0}.'.format(MISP_TAG))
        return

    epo = EPO()
    status, policy_res = epo.request('policy.find', data={'searchText': EPO_POLICY_NAME})
    if status != 200:
        logger.info('ERROR: Could not run ePO API request. Error: {} - {}'.format(str(status), policy_res))
        return
    policy_res_json = json.loads(policy_res.text.strip('OK:'))

    if len(policy_res_json) > 1:
        logger.info('ERROR: Found multiple policies with the same name. Please be more specific.')
        return
    elif len(policy_res_json) < 1:
        logger.info('STATUS: Policy does not exist. Please create policy manually and assign to the right systems.')
        return
    else:
        logger.debug('STATUS: Identified policy. Going to download, make changes and upload policy again.')
        productId = policy_res_json[0]['productId']
        status, policy_exp = epo.request('policy.export', params={'productId': productId})
        if status != 200:
            logger.info('ERROR: Could not export policy. Error: {} - {}'.format(str(status), policy_exp))
            return

        policy_exp_json = json.loads(policy_exp.text.strip('OK:'))

        with open('exports/policy_old.xml', 'w') as output:
            output.write(policy_exp_json)
        output.close()

        epo.prep_xml()
        logger.debug('STATUS: Successfully made changes to the policy. Trying to upload.')

        status, policy_import = epo.request('policy.importPolicy', params={'force': True},
                                            files={'file': ('policy_new.xml', open('exports/policy_new.xml', 'rb'),
                                                            'multipart/form-data')})

        if status != 200:
            logger.info('ERROR: Could not import new policy. Error: {} - {}'.format(str(status), policy_import))
            return
        else:
            logger.info('SUCCESS: Successful import new policy in ePO.')


if __name__ == '__main__':
    while True:
        main()
        time.sleep(60)