#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(234622);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/18");

  script_cve_id("CVE-2025-29983", "CVE-2025-29984");
  script_xref(name:"IAVA", value:"2025-A-0277");

  script_name(english:"Dell Trusted Device < 7.0.3.0 Multiple Vulnerabilities (DSA-2025-151)");

  script_set_attribute(attribute:"synopsis", value:
"Dell Trusted Device installed on the local host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Dell Trusted Device installed on the remote host is prior to 7.0.3.0. It is, therefore, affected by
multiple vulnerabilities as referenced in the DSA-2025-151 advisory.

  - Dell Trusted Device, versions prior to 7.0.3.0, contain an Incorrect Default Permissions vulnerability. A
    low privileged attacker with local access could potentially exploit this vulnerability, leading to
    Elevation of privileges. (CVE-2025-29984)

  - Dell Trusted Device, versions prior to 7.0.3.0, contain an Improper Link Resolution Before File Access
    ('Link Following') vulnerability. A low privileged attacker with local access could potentially exploit
    this vulnerability, leading to Elevation of privileges. (CVE-2025-29983)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.dell.com/support/kbdoc/en-us/000299528/dsa-2025-151");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Dell Trusted Device version 7.0.3.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-29983");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/04/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:dell:trusted_device_agent");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:dell:bios_verification");

  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("dell_trusted_device_win_installed.nbin");
  script_require_keys("installed_sw/Dell Trusted Device");

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
      'product': {'name': 'Dell Trusted Device', 'type': 'app'},
      'check_algorithm': 'default',
      'constraints': [
        {'fixed_version': '7.0.3.0'}
      ]
    }
  ]
};
var result = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_HOLE);
vdf::handle_check_and_report_errors(vdf_result:result);
