#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(197483);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/20");

  script_cve_id("CVE-2024-28165", "CVE-2024-33004");
  script_xref(name:"IAVA", value:"2024-A-0277");

  script_name(english:"SAP BusinessObjects Business Intelligence Platform Multiple Vulnerabilities (May 2024)");

  script_set_attribute(attribute:"synopsis", value:
"The SAP business intelligence product installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of SAP BusinessObjects Business Intelligence Platform installed on the remote Windows host is potentially
affected by the following vulnerabilities:

  - A cross-site scripting (XSS) vulnerability exists in the Opendocument URL due to improper validation of user-supplied
   input before returning it to users. An unauthenticated, remote attacker can exploit this, by convincing a user to
   click a specially crafted URL, to impact the confidentiality and integrity of the applicaiton within a user's browser
   session.

 - A insecure storage vulnerability exists in due to caching dynamic web pages after logout. An unauthenticated, physical
   attacker can exploit this to see sensitive information and open pages of the applicaiton.

Note that Nessus has not attempted to exploit these issues but has instead relied only on the application's
self-reported version number.");
  # https://support.sap.com/en/my-support/knowledge-base/security-notes-news/may-2024.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5395e9d1");
  script_set_attribute(attribute:"see_also", value:"https://launchpad.support.sap.com/#/notes/3431794");
  script_set_attribute(attribute:"see_also", value:"https://launchpad.support.sap.com/#/notes/3449093");
  script_set_attribute(attribute:"solution", value:
"See vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-28165");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sap:businessobjects_business_intelligence_platform");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("sap_business_objects_intelligence_platform_win_installed.nbin");
  script_require_keys("installed_sw/SAP BusinessObjects Business Intelligence Platform", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'SAP BusinessObjects Business Intelligence Platform', win_local:TRUE);

# https://launchpad.support.sap.com/#/notes/0001602088 for translations
var constraints = [
  { 'min_version': '14.3.3', 'fixed_version': '14.3.3.9999', 'fixed_display': '4.3 SP003 001100', 'require_paranoia': TRUE}, # patch mapping not available yet
  { 'min_version': '14.3.4', 'fixed_version': '14.3.4.4938', 'fixed_display': '4.3 SP004 000400'},
  { 'min_version': '14.3.5', 'fixed_version': '14.3.5.9999', 'fixed_display': '4.3 SP005 000000', 'require_paranoia': TRUE} # patch mapping not available yet
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE,
  flags:{'xss':TRUE}
);
