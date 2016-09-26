# standard libraries
import argparse
import sys
import json
import os
from collections import OrderedDict


# project libraries
from lib import deepsecurity as deepsecurity


def get_arg_parser(prog='vulssimulator_ds.py', description=None, add_help=False):
    """
    Create a standardized argument parser
    """
    if not description:
        description = """
    Find out coverage with Deep Security against high urgency vulnerability that Vuls reports
"""

    parser = argparse.ArgumentParser(
        prog=prog, description=description, add_help=add_help)

    # Deep Security arguments
    parser.add_argument('-d', '--dsm', action='store', default='app.deepsecurity.trendmicro.com',
                        required=False, help='The address of the Deep Security Manager. Defaults to Deep Security as a Service')
    parser.add_argument('--dsm-port', action='store', default='4119', dest='dsm_port', required=False,
                        help='The address of the Deep Security Manager. Defaults to an AWS Marketplace/software install (:4119). Automatically configured for Deep Security as a Service')
    parser.add_argument('-u', '--dsm-username', action='store', default=None, dest='dsm_username', required=True,
                        help='The Deep Security username to access the IP Lists with. Should only have read-only rights to IP lists and API access')
    parser.add_argument('-p', '--dsm-password', action='store', default=None, dest='dsm_password', required=True,
                        help='The password for the specified Deep Security username. Should only have read-only rights to IP lists and API access')
    parser.add_argument('-t', '--dsm-tenant', action='store', default=None,
                        dest='dsm_tenant', required=False, help='The name of the Deep Security tenant/account')

    # Vuls arguments
    parser.add_argument('-v', '--vuls-json-report', action='store', default=None,
                        dest='vuls_report', required=True, help='The full-path of JSON format report by Vuls')

    # Output arguments
    parser.add_argument('-o', '--output-directory', action='store', default=os.getcwd(), dest='output_directory',
                        required=False, help='The full-path of directory to output results. Defaults to current directory')

    # general structure arguments
    parser.add_argument('--ignore-ssl-validation', action='store_true', dest='ignore_ssl_validation', required=False,
                        help='Ignore SSL certification validation. Be careful when you use this as it disables a recommended security check. Required for Deep Security Managers using a self-signed SSL certificate')
    parser.add_argument('--verbose', action='store_true', required=False,
                        help='Enabled verbose output for the script. Useful for debugging')

    return parser


class ScriptContext():

    """
    Context for a command line script.
    """

    def __init__(self, args, parser):
        self.parser = parser
        self._passed_args = args
        self.args = parser.parse_args(self._passed_args)
        self.dsm = None
        self.vuls_cve_list = None

    def __del__(self):
        """
        clean up on object destruction
        """
        self.clean_up()

    def clean_up(self):
        """
        Gracefully dispose of the script's context
        """
        if 'dsm' in dir(self) and self.dsm:
            try:
                self.dsm.sign_out()
            except Exception as err:
                pass

    def _log(self, msg, err=None, priority=False):
        """
        Output log message for the specified event
        """
        if priority or self.args.verbose or err:
            if err:
                print(("{}.\nThrew an exception --> {}".format(msg, err)))
                self.clean_up()
                sys.exit(1)
            else:
                print(msg)

    def print_help(self):
        """
        Print the command line syntax available to the user
        """
        self.parser.print_help()

    def _connect_to_deep_security(self):
        dsm = None
        if self.args.ignore_ssl_validation:
            self._log("""************************************************************************
* IGNORING SSL CERTIFICATE VALIDATION
* ===================================
* You have requested to ignore SSL certificate validation. This is a
* less secure method of connecting to a Deep Security Manager (DSM).
* Please ensure that you have other mitigations and security controls
* in place (like restricting IP space that can access the DSM,
* implementing least privilege for the Deep Security user/role
* accessing the API, etc).
*
* During script execution, you'll see a number of
* "InsecureRequestWarning" messages. These are to be expected when
* operating without validation.
************************************************************************""", priority=True)
        try:
            dsm_port = self.args.dsm_port if not self.args.dsm == 'app.deepsecurity.trendmicro.com' else 443
            self._log("Attempting to connect to Deep Security at {}:{}".format(
                self.args.dsm, dsm_port))
            dsm = deepsecurity.dsm.Manager(hostname=self.args.dsm, port=dsm_port, username=self.args.dsm_username,
                                           password=self.args.dsm_password, tenant=self.args.dsm_tenant, ignore_ssl_validation=self.args.ignore_ssl_validation)
            dsm.sign_in()
        except Exception as err:
            self._log("Could not connect to the Deep Security", err=err)

        if not dsm._sessions['REST'] and not dsm._sessions['SOAP']:
            if not self.args.ignore_ssl_validation:
                self._log(
                    "Unable to connect to the Deep Security Manager. Please check your settings")
                self._log(
                    "You did not ask to ignore SSL certification validation. This is a common error when connect to a Deep Security Manager that was installed via software or the AWS Marketplace. Please set the flag (--ignore-ssl-validation), check your other settings, and try again", err="SslValidation or ConnectError")
            else:
                self._log(
                    "Unable to connect to the Deep Security Manager. Please check your settings", err="ConnectError")
        else:
            self._log(
                "Connected to the Deep Security Manager at {}".format(self.args.dsm))

        return dsm

    def _read_vuls_json_report(self):
        """
        Read JSON report made by Vuls and return the list of cves
        """
        vuls_cve_list = []
        cve_scores = []
        severity = ''

        try:
            with open(self.args.vuls_report) as tmp_file:
                vuls_json_report = json.load(tmp_file)
        except Exception as err:
            self._log(
                "Could not read the report({})".format(self.args.vuls_report), err=err)

        for cves in vuls_json_report['KnownCves']:
            cve_scores = [
                cves['CveDetail']['Nvd']['Score'], cves['CveDetail']['Jvn']['Score']]
            if max(cve_scores) >= 7.0:
                severity = 'High'
            elif max(cve_scores) >= 4.0:
                severity = 'Midium'
            else:
                severity = 'Low'
            target_cve = OrderedDict()
            target_cve['Id'] = cves['CveDetail']['CveID']
            target_cve['Severity'] = severity
            vuls_cve_list.append(target_cve)
        return vuls_cve_list

    def _output_file(self, output_file_name, output_string):
        """
        Output strings to the assigned file
        """
        output_dir = self.args.output_directory
        if os.path.exists(output_dir):
            try:
                with open(output_dir+'/'+output_file_name, "a") as tmp_file:
                    tmp_file.write(output_string)
            except Exception as err:
                self._log("Could not output to{}".format(
                    output_dir+'/'+ourput_file_name), err=err)
        else:
            self._log("Could not find Output_dir({})".format(
                output_dir), err='No Directroy Error')
        return 0
