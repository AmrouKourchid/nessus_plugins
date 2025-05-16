#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(235661);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/09");

  script_cve_id("CVE-2025-2775", "CVE-2025-2776", "CVE-2025-2777");
  script_xref(name:"IAVA", value:"2025-A-0315");

  script_name(english:"SysAid Server < 24.4.60 b16 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The inventory management server on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of SysAid Server installed on the remote host is prior to 24.4.60 b16. It is, therefore, affected multiple
vulnerabilities, including the following:

  - SysAid On-Prem versions <= 23.3.40 are vulnerable to an unauthenticated XML External Entity (XXE)
    vulnerability in the Checkin processing functionality, allowing for administrator account takeover and
    file read primitives. (CVE-2025-2775)

  - SysAid On-Prem versions <= 23.3.40 are vulnerable to an unauthenticated XML External Entity (XXE)
    vulnerability in the Server URL processing functionality, allowing for administrator account takeover
    and file read primitives. (CVE-2025-2776)

  - SysAid On-Prem versions <= 23.3.40 are vulnerable to an unauthenticated XML External Entity (XXE)
    vulnerability in the lshw processing functionality, allowing for administrator account takeover and file
    read primitives. (CVE-2025-2777)
  
Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://documentation.sysaid.com/docs/24-40-60");
  script_set_attribute(attribute:"see_also", value:"https://thehackernews.com/2025/05/sysaid-patches-4-critical-flaws.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to SysAid Server 24.4.60 b16 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:L");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-2777");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/05/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/03/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/05/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sysaid:sysaid_on-premises");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("sysaid_server_win_installed.nbin");
  script_require_keys("installed_sw/SysAid Server", "SMB/Registry/Enumerated");

  exit(0);
}

include('vdf.inc');

# @tvdl-content
var vuln_data = {
  'metadata': {'spec_version': '1.0'},
  'checks': [
    {
      'product': {'name': 'SysAid Server', 'type': 'app'},
      'check_algorithm': 'default',
      'constraints': [
        {'max_version': '23.3.40.99999', 'fixed_version': '24.4.60 b16'}
      ]
    }
  ]
};
var result = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_HOLE);
vdf::handle_check_and_report_errors(vdf_result:result);
