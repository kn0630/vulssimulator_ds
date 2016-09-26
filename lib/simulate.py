# standard libraries
import datetime
from collections import OrderedDict

# project libraries
from . import core


def run_script(args):
    # configure the command line args
    parser = core.get_arg_parser(
        prog='vulssimulator_ds.py simulate', add_help=True)
    script = Script(args[1:], parser)

    # Get CVE list from the report of Vuls
    script.get_cves_from_vuls()

    # Get CVE list from Deep Security
    script.connect()
    in_ds = script.get_cves_in_ds()

    # Compere CVE lists from Vuls with from Deep Security
    covered_cves, uncovered_cves, covered_severity, uncovered_severity = script.compare_cves(
        in_ds)

    # Output summary and detail to assigned files
    timestamp = datetime.datetime.today().strftime('%Y%m%d%H%M%S')
    output_summary = script.make_summary(
        covered_cves, uncovered_cves, covered_severity, uncovered_severity, in_ds)

    script._output_file(
        'vulssimulator_ds-summary_'+timestamp+'.log', output_summary)

    output_covered_detail = script.make_detail(covered_cves)
    script._output_file(
        'vulssimulator_ds-covered_'+timestamp+'.log', output_covered_detail)

    output_uncovered_detail = script.make_detail(uncovered_cves)
    script._output_file(
        'vulssimulator_ds-uncovered_'+timestamp+'.log', output_uncovered_detail)

    # Clean up
    script.clean_up()

    return 0


class Script(core.ScriptContext):

    def __init__(self, args, parser):
        core.ScriptContext.__init__(self, args, parser)
        self.dsm = None
        self.vuls_cve_list = None

    def get_cves_from_vuls(self):
        """
        Get a list of vulnerability on this machine from report of Vuls
        """
        self.vuls_cve_list = self._read_vuls_json_report()

    def connect(self):
        """
        Connect to Deep Security
        """
        self.dsm = self._connect_to_deep_security()

    def get_cves_in_ds(self):
        """
        Get a list of available CVE coverage with Deep Security
        """
        cves = []

        if self.dsm:
            self.dsm.rules.get()
            for rule_id, rule in list(self.dsm.rules['intrusion_prevention'].items()):
                if rule.cve_numbers:
                    for cve in rule.cve_numbers:
                        cves.append(cve)

        return cves

    def compare_cves(self, in_ds):
        """
        Compare lists of CVEs between vulnerability report and coverage with Deep Security
        """
        covered_cve_list = []
        uncovered_cve_list = []
        coverage_severity = {'High': 0, 'Medium': 0, 'Low': 0}
        uncoverage_severity = {'High': 0, 'Medium': 0, 'Low': 0}

        if self.vuls_cve_list:
            for target_cve in self.vuls_cve_list:
                if target_cve['Id'] in in_ds:
                    covered_cve_list.append(target_cve)
                    if target_cve['Severity'] == 'High':
                        coverage_severity['High'] += 1
                    elif target_cve['Severity'] == 'Medium':
                        coverage_severity['Medium'] += 1
                    else:
                        coverage_severity['Low'] += 1
                else:
                    uncovered_cve_list.append(target_cve)
                    if target_cve['Severity'] == 'High':
                        uncoverage_severity['High'] += 1
                    elif target_cve['Severity'] == 'Medium':
                        uncoverage_severity['Medium'] += 1
                    else:
                        uncoverage_severity['Low'] += 1
        else:
            self._log("Could not find vulnerability by Vuls in the report",
                      err="No vulnerability by Vuls")
        return covered_cve_list, uncovered_cve_list, coverage_severity, uncoverage_severity

    def make_summary(self, covered_cves, uncovered_cves, covered_severity, uncovered_severity, in_ds):
        """
        Print the summary of coverage and uncoverage with Deep Security
        """
        coverage_percentage = (
            len(covered_cves)/len(self.vuls_cve_list)) * 100
        uncoverage_percentage = (
            len(uncovered_cves)/len(self.vuls_cve_list)) * 100
        output_string = "\n***********************************************************************"
        output_string += "\n* Coverage Summary"
        output_string += "\n***********************************************************************"
        output_string += "\nVulnerability found by Vuls are {} CVEs".format(
            len(self.vuls_cve_list))
        output_string += "\nDeep Security's intrusion prevention rule set currently looks for {} CVEs".format(
            len(in_ds))
        output_string += "\n"
        output_string += "\n{} ({:.2f}%) of the CVEs that Vuls found are covered with Deep Security".format(
            len(covered_cves), coverage_percentage)
        output_string += "\nSeverity Summary --> High : {} CVEs, Medium : {} CVEs, Low : {} CVEs".format(
            covered_severity['High'], covered_severity['Medium'], covered_severity['Low'])
        output_string += "\n"
        output_string += "\n{} ({:.2f}%) of the CVEs that Vuls are uncovered with Deep Security, and remain as vulnerability".format(
            len(uncovered_cves), uncoverage_percentage)
        output_string += "\nSeverity Summary --> High : {} CVEs, Medium : {} CVEs, Low : {} CVEs".format(
            uncovered_severity['High'], uncovered_severity['Medium'], uncovered_severity['Low'])
        output_string += "\n"
        print(output_string)
        return output_string

    def make_detail(self, cves):
        """
        Print the detail of CVEs that Deep Security covers and uncovers.
        """
        cve = ''
        output_detail = "CveId,Severity\n"
        for cve in cves:
            output_detail += ",".join(cve.values())
            output_detail += "\n"
        return output_detail
