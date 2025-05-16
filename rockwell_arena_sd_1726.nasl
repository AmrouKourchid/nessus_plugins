#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(234500);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/17");

  script_cve_id(
    "CVE-2025-2285",
    "CVE-2025-2286",
    "CVE-2025-2287",
    "CVE-2025-2288",
    "CVE-2025-2293",
    "CVE-2025-2829",
    "CVE-2025-3285",
    "CVE-2025-3286",
    "CVE-2025-3287",
    "CVE-2025-3288",
    "CVE-2025-3289"
  );
  script_xref(name:"IAVB", value:"2025-B-0057");

  script_name(english:"Rockwell Automation Arena < 16.20.09 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"An updater application installed on the remote Windows host is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Rockwell Automation Arena installed on the remote Windows host is prior to 
16.20.09. It is, therefore, affected by a multiple vulnerabilities

  - A local code execution vulnerability exists in the affected products due to an uninitialized pointer. 
    The flaw is result of improper validation of user-supplied data.  If exploited a threat actor can 
    disclose information and execute arbitrary code on the system. To exploit the vulnerability a legitimate 
    user must open a malicious DOE file. (CVE-2025-2285, CVE-2025-2286, CVE-2025-2287)

  - A local code execution vulnerability exists in the affected products due to a threat actor being able to 
    write outside of the allocated memory buffer. The flaw is a result of improper validation of 
    user-supplied data.   If exploited a threat actor can disclose information and execute arbitrary code on 
    the system. To exploit the vulnerability a legitimate user must open a malicious DOE file. 
    (CVE-2025-2288, CVE-2025-2829)

  - A local code execution vulnerability exists in the affected products due to a threat actor being able to 
    read outside of the allocated memory buffer. The flaw is a result of improper validation of user-supplied 
    data.  If exploited a threat actor can disclose information and execute arbitrary code on the system. To 
    exploit the vulnerability a legitimate user must open a malicious DOE file. (CVE-2025-3285)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://www.rockwellautomation.com/en-us/trust-center/security-advisories/advisory.SD1726.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dedf139a");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Rockwell Automation Arena 16.20.09 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-2285");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/04/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:rockwellautomation:arena");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("rockwell_arena_win_installed.nbin");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/Rockwell Arena");

  exit(0);
}

include('vdf.inc');

# @tvdl-content
var vuln_data = {
  'metadata': {'spec_version': '1.0'},
  'requires': [
    {'scope': 'target', 'match': {'os': 'windows'}}
  ],
  'checks': [
    {
      'product': {'name': 'Rockwell Arena', 'type': 'app'},
      'check_algorithm': 'default',
      'constraints' : [
        {'fixed_version' : '16.20.09'}
      ]
    }
  ]
};

var vdf_result = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_HOLE);
vdf::handle_check_and_report_errors(vdf_result:vdf_result);
