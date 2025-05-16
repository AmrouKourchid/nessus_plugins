#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(234803);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/24");

  script_cve_id("CVE-2025-31498");
  script_xref(name:"IAVA", value:"2025-A-0250");

  script_name(english:"c-ares 1.32.3 < 1.34.5 Use After Free (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of c-ares installed on the remote host is affected by a use after free vulnerability. c-ares is an 
asynchronous resolver library. From 1.32.3 through 1.34.4, there is a use-after-free in read_answers() when 
process_answer() may re-enqueue a query either due to a DNS Cookie Failure or when the upstream server does not 
properly support EDNS, or possibly on TCP queries if the remote closed the connection immediately after a response. If 
there was an issue trying to put that new transaction on the wire, it would close the connection handle, but 
read_answers() was still expecting the connection handle to be available to possibly dequeue other responses. In theory 
a remote attacker might be able to trigger this by flooding the target with ICMP UNREACHABLE packets if they also 
control the upstream nameserver and can return a result with one of those conditions, this has been untested. Otherwise 
only a local attacker might be able to change system behavior to make send()/write() return a failure condition. This 
vulnerability is fixed in 1.34.5.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://github.com/c-ares/c-ares/security/advisories/GHSA-6hxc-62jh-p29v
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?816bce07");
  script_set_attribute(attribute:"solution", value:
"Upgrade to c-ares version 1.34.5 or later.");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:L/VI:L/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-31498");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/04/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:c-ares_project:c-ares");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macos_c-ares_installed.nbin");
  script_require_keys("installed_sw/c-ares", "Host/MacOSX/Version");

  exit(0);
}

include('vdf.inc');

# @tvdl-content
var vuln_data = {
  'metadata': {'spec_version': '1.0'},
  'requires': [
    {'scope': 'target', 'match': {'os': 'macos'}}
  ],
  'checks': [
    {
      'product': {'name': 'c-ares', 'type': 'app'},
      'check_algorithm': 'default',
      'constraints': [
        { 'min_version': '1.32.3', 'fixed_version' : '1.34.5' }
      ]
    }
  ]
};

var result = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_HOLE);
vdf::handle_check_and_report_errors(vdf_result:result);
