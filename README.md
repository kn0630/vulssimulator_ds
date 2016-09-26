# Vuls simulator for Deep Security

Simulate Deep Security's coverage for high urgency vulnerability reported by [Vuls](https://github.com/future-architect/vuls).

(This tool is refer to [Amazon Inspector with DeepSecurity](https://github.com/deep-security/amazon-inspector) and [DeepSecurity SDK](https://github.com/deep-security/deep-security-py).)

----


## Description
```vulssimulator_ds``` is a CLI tool that simulates Deep Security's coverage for the vulenarebility reported by [Vuls](https://github.com/future-architect/vuls).

It can help you to see the toughness of Deep Security, and find out vulnerability be required another countermeasures.

This tool use [DeepSecurity SDK](https://github.com/deep-security/deep-security-py) and refer to [Amazon Inspector with DeepSecurity](https://github.com/deep-security/amazon-inspector).


##Features
* Output vulnerability that Deep Security can and cannot cover.
    * To use report by Vuls, we can simulate for necessary and sufficient vulnerability.
* Three types of output style are available.
    1. Summary list : Output the number of the server's vulnerability, coverage and uncoverage by Deep Security, and so.
    2. Coverage CVE list : Output CVE list that Deep Security can cover.
    3. Uncoverage CVE list : Output CVE list that Deep Security cannnot cover.


##Requirement
* Python3 or more
* Accessible Deep Security Manager ("Deep Security As A Service" is also okay.)
* JSON-format report of [Vuls](https://github.com/future-architect/vuls)

----

## Index
- [Usage](#usage)
    - [simulate](#usage-simulate)
- [SSL Certificate Validation](#ssl-certificate-validation)


## Usage
The syntax for basic command line usage is available by using the ```--help``` switch.

```bash
$ python vulssimulator_ds.py help
usage: python vulssimulator_ds.py [COMMAND]
   For more help on a specific command, type "python vulssimulator_ds.py [COMMAND] --help"

   Available commands:

   simulate
      > Compare the vulenarebility reported by Vuls with The CVE list Deep Security has, and output the result.

```

Each script in this set works under a common structure. There are several shared arguments;

```bash
  -h, --help
         - show this help message and exit
  -d [DSM], --dsm [DSM]
         - The address of the Deep Security Manager. Defaults to Deep Security as a Service
  --dsm-port [DSM_PORT]
         - The address of the Deep Security Manager.
           Defaults to an AWS Marketplace/software install (:4119).
           Automatically configured for Deep Security as a Service.
  -u [DSM_USERNAME], --dsm-username [DSM_USERNAME]
         - The Deep Security username to access the IP Lists with.
           Should only have read-only rights to IP lists and API access.
  -p [DSM_PASSWORD], --dsm-password [DSM_PASSWORD]
         - The password for the specified Deep Security username.
           Should only have read-only rights to IP lists and API access.
  -t [DSM_TENANT], --dsm-tenant [DSM_TENANT]
         - The name of the Deep Security tenant/account
  -v [VULS_JSON_REPORT_PATH], --vuls-json-report [VULS_JSON_REPORT_PATH]
         - The full-path of JSON format report by Vuls
  -o OUTPUT_DIRECTORY, --output-directory OUTPUT_DIRECTORY
         - The full-path of directory to output results. Defaults to current directory.
  --ignore-ssl-validation
         - Ignore SSL certification validation.
           Be careful when you use this as it disables a recommended security check.
           Required for Deep Security Managers using a self-signed SSL certificate.
  --verbose
         - Enabled verbose output for the script. Useful for debugging.
```

These core settings allow you to connect to a Deep Security manager or Deep Security as a Service.

```bash
# to connect to your own Deep Security manager
vulssimulator_ds.py [COMMAND] -d 10.1.1.0 -u admin -p USE_RBAC_TO_REDUCE_RISK --ignore-ssl-validation

# to connect to Deep Security as a Service
vulssimulator_ds.py [COMMAND] -u admin -p USE_RBAC_TO_REDUCE_RISK -t MY_ACCOUNT
```

Each individual command will also have it's own options that allow you to control the behaviour of the command.

You'll notice in the examples, the password is set to USE_RBAC_TO_REDUCE_RISK. In this context, RBAC stands for role based access control.

Currently Deep Security treats API access just like a user logging in. Therefore it is strongly recommended that you create a new Deep Security user for use with this script. This user should have the bare minimum permissions required to complete the tasks.


<a name="usage-simulate" />

### simulate

The simulate command gets the vulnerability repoted by Vuls and the list of CVEs that Deep Securty can mitigate.
After that, this tool compares vulnerability with Deep Security's coverage.

(Deep Security focuses on the mitigate of *remotely exploitable* vulnerability using it's intrusion prevention engine.)

```
# Output result of comparison the vulnerability with Deep Security as a Service
python vulssimulator_ds.py simulate -u USER -p PASSWORD -t TENANT -v /tmp/vuls/results/current/0-0-0-0.json -o /tmp

# ...for another Deep Security manager
python vulssimulator_ds.py compare -u USER -p PASSWORD -d DSM_HOSTNAME -v /tmp/vuls/results/current/0-0-0-0.json -o /tmp --ignore-ssl-validation
```

This will generate output along the lines of;

```
***********************************************************************
* Coverage Summary
***********************************************************************
Vulnerability found by Vuls are 95 CVEs
Deep Security's intrusion prevention rule set currently looks for 5332 CVEs

6 (6.32%) of the CVEs that Vuls found are covered with Deep Security
Severity Summary --> High : 1 CVEs, Medium : 0 CVEs, Low : 5 CVEs

89 (93.68%) of the CVEs that Vuls are uncovered with Deep Security, and remain as vulnerability
Severity Summary --> High : 20 CVEs, Medium : 0 CVEs, Low : 69 CVEs
```

When we use this tool, not only summary but also detail are output to the assigned Directroy.
So we can also see which CVEs are covered by Deep Security, and are uncovered.
Those generate output along the lines of;

```
CveId,Severity
CVE-2016-0705,High
CVE-2016-0749,High
CVE-2016-0799,High
CVE-2016-2108,High
...
CVE-2015-7872,Low
CVE-2015-8629,Low
CVE-2016-0702,Low
CVE-2015-4792,Low
CVE-2016-0609,Low
```

<a name="ssl-certificate-validation" />

## SSL Certificate Validation

If the Deep Security Manager (DSM) you're connecting to was installed via software of the AWS Marketplace, there's a chance that it is still using the default, self-signed SSL certificate. By default, python checks the certificate for validity which it cannot do with self-signed certificates.

If you are using self-signed certificates, please use the new ```--ignore-ssl-validation``` command line flag.

When you use this flag, you're telling python to ignore any certificate warnings. These warnings should be due to the self-signed certificate but *could* be for other reasons. It is strongly recommended that you have alternative mitigations in place to secure your DSM.

When the flag is set, you'll see this warning block;

```bash
***********************************************************************
* IGNORING SSL CERTIFICATE VALIDATION
* ===================================
* You have requested to ignore SSL certificate validation. This is a less secure method
* of connecting to a Deep Security Manager (DSM). Please ensure that you have other
* mitigations and security controls in place (like restricting IP space that can access
* the DSM, implementing least privilege for the Deep Security user/role accessing the
* API, etc).
*
* During script execution, you'll see a number of "InsecureRequestWarning" messages.
* These are to be expected when operating without validation.
***********************************************************************
```

And during execution you may see lines similar to;

```python
.../requests/packages/urllib3/connectionpool.py:789: InsecureRequestWarning: Unverified HTTPS request is being made. Adding certificate verification is strongly advised. See: https://urllib3.readthedocs.org/en/latest/security.html
```

These are expected warnings. Can you tell that we (and the python core teams) are trying to tell you something? If you're interesting in using a valid SSL certificate, you can get one for free from [Let's Encrypt](https://letsencrypt.org), [AWS themselves](https://aws.amazon.com/certificate-manager/) (if your DSM is behind an ELB), or explore commercial options (like the [one from Trend Micro](http://www.trendmicro.com/us/enterprise/cloud-solutions/deep-security/ssl-certificates/)).

----

## References / Related Projects
* [Vuls](https://github.com/future-architect/vuls)
* [DeepSecurity SDK](https://github.com/deep-security/deep-security-py)
* [Amazon Inspector with DeepSecurity](https://github.com/deep-security/amazon-inspector)

----

## Author
[kn0630](https://github.com/kn0630)

## Licence
Please see [LICENSE](https://github.com/kn0630/vulssimulator_ds/LICENSE)

