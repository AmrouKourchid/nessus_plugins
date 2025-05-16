#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(207852);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/12");

  script_cve_id("CVE-2024-28166", "CVE-2024-41731", "CVE-2024-42375");
  script_xref(name:"IAVA", value:"2024-A-0617");

  script_name(english:"SAP BusinessObjects Business Intelligence Platform Multiple Vulnerabilities (3433545)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The version of SAP BusinessObjects Business Intelligence Platform installed on the remote host is prior to 4.2 SP009
001900, 4.3 SP003 001200, 4.3 SP004 000600, or 4.3 SP005 000000. It is, therefore, affected by multiple vulnerabilities
as referenced in the 3433545 and 3515653 advisories.

  - SAP BusinessObjects Business Intelligence Platform allows an authenticated attacker to upload malicious
  code over the network, that could be executed by the application. On successful exploitation, the attacker
  can cause a low impact on the Integrity of the application. (CVE-2024-42375)

  - SAP BusinessObjects Business Intelligence Platform allows an unauthenticated attacker to upload malicious
  files to BI file repository over the network. For an attacker to bypass the front-end file format check, in
  depth system knowledge is required. On successful exploitation, the attacker could modify some data causing
  low impact on Integrity of the application. (CVE-2024-28166)

  - SAP BusinessObjects Business Intelligence Platform allows an authenticated attacker to upload malicious 
  files to BI file repository over the network. For an attacker to bypass the front-end file format check, in
  depth system knowledge is required. On successful exploitation, the attacker could modify some data causing
  low impact on Integrity of the application. (CVE-2024-41731)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://launchpad.support.sap.com/#/notes/3433545");
  script_set_attribute(attribute:"see_also", value:"https://launchpad.support.sap.com/#/notes/3515653");
  script_set_attribute(attribute:"solution", value:
"Upgrade to SAP BusinessObjects Business Intelligence Platform version 4.2 SP009 001900 / 4.3 SP003 001200 / 4.3 SP004
000600 / 4.3 SP005 000000 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-42375");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/08/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sap:businessobjects_business_intelligence_platform");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("sap_business_objects_intelligence_platform_win_installed.nbin");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/SAP BusinessObjects Business Intelligence Platform");

  exit(0);
}

include('vcf.inc');
get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'SAP BusinessObjects Business Intelligence Platform', win_local:TRUE);

# https://launchpad.support.sap.com/#/notes/0001602088 for translations
var constraints = [
  { 'min_version' : '14.2', 'fixed_version' : '14.2.9.4953', 'fixed_display' : '4.2 SP009 001900' },
  { 'min_version' : '14.3', 'fixed_version' : '14.3.3.4992', 'fixed_display' : '4.3 SP003 001200' },
  { 'min_version' : '14.3.4', 'fixed_version' : '14.3.4.5099', 'fixed_display' : '4.3 SP004 000800' },
  { 'min_version' : '14.3.5', 'fixed_version' : '14.3.5.9999', 'fixed_display' : '4.3 SP005 000000' , 'require_paranoia': TRUE}, # patch mapping not available yet
  { 'min_version' : '15.0.0', 'fixed_version' : '15.0.0.9999', 'fixed_display' : '2025 SP000 000000', 'require_paranoia': TRUE} # patch mapping not available yet
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
