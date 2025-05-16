#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(217080);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/03");

  script_cve_id("CVE-2009-0217");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2009-0217");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - The design of the W3C XML Signature Syntax and Processing (XMLDsig) recommendation, as implemented in
    products including (1) the Oracle Security Developer Tools component in Oracle Application Server
    10.1.2.3, 10.1.3.4, and 10.1.4.3IM; (2) the WebLogic Server component in BEA Product Suite 10.3, 10.0 MP1,
    9.2 MP3, 9.1, 9.0, and 8.1 SP6; (3) Mono before 2.4.2.2; (4) XML Security Library before 1.2.12; (5) IBM
    WebSphere Application Server Versions 6.0 through 6.0.2.33, 6.1 through 6.1.0.23, and 7.0 through 7.0.0.1;
    (6) Sun JDK and JRE Update 14 and earlier; (7) Microsoft .NET Framework 3.0 through 3.0 SP2, 3.5, and 4.0;
    and other products uses a parameter that defines an HMAC truncation length (HMACOutputLength) but does not
    require a minimum for this length, which allows attackers to spoof HMAC-based signatures and bypass
    authentication by specifying a truncation length with a small number of bits. (CVE-2009-0217)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2009-0217");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info2.nasl");
  script_require_keys("Host/cpu", "Host/local_checks_enabled", "global_settings/vendor_unpatched");
  script_require_ports("Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}
include('vdf.inc');

# @tvdl-content
var vuln_data = {
 "metadata": {
  "spec_version": "1.0p"
 },
 "requires": [
  {
   "scope": "scan_config",
   "match": {
    "vendor_unpatched": true
   }
  },
  {
   "scope": "target",
   "match": {
    "os": "linux"
   }
  }
 ],
 "report": {
  "report_type": "unpatched"
 },
 "checks": [
  {
   "product": {
    "name": "xmlsec1",
    "type": "rpm_package"
   },
   "check_algorithm": "rpm",
   "constraints": [
    {
     "requires": [
      {
       "scope": "target",
       "match": {
        "distro": "redhat"
       }
      },
      {
       "scope": "target",
       "match": {
        "os_version": "4"
       }
      }
     ]
    }
   ]
  },
  {
   "product": {
    "name": [
     "java-1.6.0-openjdk",
     "xmlsec1"
    ],
    "type": "rpm_package"
   },
   "check_algorithm": "rpm",
   "constraints": [
    {
     "requires": [
      {
       "scope": "target",
       "match": {
        "distro": "redhat"
       }
      },
      {
       "scope": "target",
       "match": {
        "os_version": "5"
       }
      }
     ]
    }
   ]
  }
 ]
};

var vdf_res = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_WARNING);
vdf::handle_check_and_report_errors(vdf_result: vdf_res);
