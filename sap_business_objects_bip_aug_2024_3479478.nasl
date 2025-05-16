#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(207851);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/11");

  script_cve_id("CVE-2024-41730");
  script_xref(name:"IAVA", value:"2024-A-0617");

  script_name(english:"SAP BusinessObjects Business Intelligence Platform Improper Authorization (3479478)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of SAP BusinessObjects Business Intelligence Platform installed on the remote host is prior to 4.3 SP004
000600 or 4.3 SP005 000000. It is, therefore, affected by a vulnerability as referenced in the 3479478 advisory.

  - In SAP BusinessObjects Business Intelligence Platform, if Single Signed On is enabled on Enterprise
    authentication, an unauthorized user can get a logon token using a REST endpoint. The attacker can fully
    compromise the system resulting in High impact on confidentiality, integrity and availability.
    (CVE-2024-41730)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://launchpad.support.sap.com/#/notes/3479478");
  script_set_attribute(attribute:"solution", value:
"Upgrade to SAP BusinessObjects Business Intelligence Platform version 4.3 SP004 000600 / 4.3 SP005 000000 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-41730");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/08/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/20");
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
  { 'min_version' : '14.3', 'fixed_version' : '14.3.4.5014', 'fixed_display' : '4.3 SP004 000600' },
  { 'min_version' : '14.3.5', 'fixed_version' : '14.3.5.9999', 'fixed_display' : '4.3 SP005 000000' , 'require_paranoia': TRUE} # patch mapping not available yet
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
