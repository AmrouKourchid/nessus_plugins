#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(205606);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/29");

  script_cve_id("CVE-2024-5487", "CVE-2024-5527", "CVE-2024-36518");
  script_xref(name:"IAVA", value:"2024-A-0502-S");

  script_name(english:"ManageEngine ADAudit Plus < Build 8110 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The version of ManageEngine ADAudit Plus installed on the remote host is prior to build 8110. It is, therefore, affected by
multiple vulnerabilities.

  - Zohocorp ManageEngine ADAudit Plus versions below 8110 are vulnerable to authenticated SQL Injection in
    attack surface analyzer's export option. (CVE-2024-5487)

  - Zohocorp ManageEngine ADAudit Plus versions below 8110 are vulnerable to authenticated SQL Injection in
    file auditing configuration. (CVE-2024-5527)

  - Zohocorp ManageEngine ADAudit Plus versions below 8110 are vulnerable to authenticated SQL Injection in
    attack surface analyzer's dashboard. (CVE-2024-36518)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://www.manageengine.com/products/active-directory-audit/cve-2024-5487.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4c74043b");
  # https://www.manageengine.com/products/active-directory-audit/cve-2024-36518.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?30c722bf");
  # https://www.manageengine.com/products/active-directory-audit/cve-2024-5527.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?02b52e56");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ManageEngine ADAudit Plus build 8110 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-5527");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/08/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/15");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zohocorp:manageengine_adaudit_plus");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("manageengine_adaudit_plus_detect.nbin", "zoho_manageengine_adaudit_plus_win_installed.nbin");
  script_require_ports("installed_sw/ManageEngine ADAudit Plus", "installed_sw/Zoho ManageEngine ADAudit Plus");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_zoho.inc');

var app_info = vcf::zoho::adaudit::get_app_info();

var constraints = [
  { 'fixed_version' : '8110' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE,
  flags:{'sqli':TRUE}
);
