#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(212114);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/05");

  script_cve_id(
    "CVE-2024-7553",
    "CVE-2024-49595",
    "CVE-2024-49597",
    "CVE-2024-49596"
  );
  script_xref(name:"IAVA", value:"2023-B-0187-S");

  script_name(english:"Dell Wyse Management Suite < 4.4.1 Multiple Vulnerabilities (DSA-2024-440)");

  script_set_attribute(attribute:"synopsis", value:
"Dell Wyse Management Suite installed on the local host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Dell Wyse Management Suite installed on the remote host is prior to 4.4.1. It is, therefore, affected by
multiple vulnerabilities as referenced in the DSA-2024-440 advisory.

  - Authentication Bypass by Capture-replay vulnerability. A high privileged attacker with remote access could 
    potentially exploit this vulnerability, leading to Denial of service. (CVE-2024-49595)
  
  - Improper Restriction of Excessive Authentication Attempts vulnerability. A high privileged attacker 
    with remote access could potentially exploit this vulnerability, leading to Protection 
    mechanism bypass. (CVE-2024-49597)

  - Missing Authorization vulnerability. A high privileged attacker with remote access could potentially exploit 
    this vulnerability, leading to Denial of service and arbitrary file deletion (CVE-2024-49596)
  
Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://www.dell.com/support/kbdoc/en-us/000244453/dsa-2024-440
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?993fb0e7");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Dell Wyse Management Suite version 4.4.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-49597");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-7553");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/11/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:dell:wyse_management_suite");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("dell_wyse_management_suite_win_installed.nbin");
  script_require_keys("installed_sw/Dell Wyse Management Suite");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Dell Wyse Management Suite', win_local:TRUE);
var constraints = [ { 'fixed_version' : '4.4.1' } ];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
