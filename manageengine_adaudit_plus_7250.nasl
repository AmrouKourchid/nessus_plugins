#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(210490);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/08");

  script_cve_id("CVE-2024-48878");
  script_xref(name:"IAVA", value:"2024-A-0703");

  script_name(english:"ManageEngine ADAudit Plus < Build 7250 SQL Injection");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of ManageEngine ADAudit Plus installed on the remote host is prior to 7.2, Build 7250. It is, therefore,
affected by SQL injection vulnerability.

  - Zohocorp ManageEngine ADManager Plus versions 7241 and prior are vulnerable to SQL Injection in Archived
    Audit Report. (CVE-2024-48878)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.manageengine.com/products/ad-manager/admanager-kb/cve-2024-48878.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?588b659c");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ManageEngine ADAudit Plus version 7.2, Build 7250 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-48878");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/11/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/07");

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
  { 'max_version' : '7241', 'fixed_version' : '7250'}
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE,
    flags:{'sqli':TRUE}
);
