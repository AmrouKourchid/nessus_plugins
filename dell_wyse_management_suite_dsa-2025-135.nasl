#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(233818);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/04");

  script_cve_id(
    "CVE-2025-29981",
    "CVE-2025-29982",
    "CVE-2025-27694",
    "CVE-2025-27693",
    "CVE-2022-4904",
    "CVE-2022-24407",
    "CVE-2023-48795",
    "CVE-2021-32050",
    "CVE-2022-44792"
  );
  script_xref(name:"IAVB", value:"2025-B-0046");

  script_name(english:"Dell Wyse Management Suite < 5.1 Multiple Vulnerabilities (DSA-2025-135)");

  script_set_attribute(attribute:"synopsis", value:
"Dell Wyse Management Suite installed on the local host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Dell Wyse Management Suite installed on the remote host is prior to 5.1. It is, therefore, affected by
multiple vulnerabilities as referenced in the DSA-2025-135 advisory.

  - Dell Wyse Management Suite, versions prior to WMS 5.1, contains an Exposure of Sensitive Information
    Through Data Queries vulnerability. An unauthenticated attacker with remote access could potentially
    exploit this vulnerability, leading to Information disclosure. (CVE-2025-29981)

  - Dell Wyse Management Suite, versions prior to WMS 5.1, contains an Insecure Inherited Permissions
    vulnerability. A low privileged attacker with local access could potentially exploit this vulnerability,
    leading to Unauthorized access. (CVE-2025-29982)

  - Dell Wyse Management Suite, versions prior to WMS 5.1, contains an Insufficient Resource Pool
    vulnerability. An unauthenticated attacker with remote access could potentially exploit this vulnerability,
    leading to Denial of service. (CVE-2025-27694)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.dell.com/support/kbdoc/en-us/000296515/dsa-2025-135");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Dell Wyse Management Suite version 5.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-29981");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/03/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/03/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:dell:wyse_management_suite");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("dell_wyse_management_suite_win_installed.nbin");
  script_require_keys("installed_sw/Dell Wyse Management Suite");

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
      'product': {'name': 'Dell Wyse Management Suite', 'type': 'app'},
      'check_algorithm': 'default',
      'constraints': [
        {'fixed_version': '5.1'}
      ]
    }
  ]
};
var result = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_HOLE);
vdf::handle_check_and_report_errors(vdf_result:result);
