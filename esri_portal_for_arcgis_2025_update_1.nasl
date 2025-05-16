#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(233867);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/04");

  script_cve_id("CVE-2025-2538");
  script_xref(name:"IAVA", value:"2025-A-0209");

  script_name(english:"Esri Portal for ArcGIS < Security 2025 Update 1 Hardcoded Credentials");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The version of Esri Portal for ArcGIS installed is missing Security 2025 Update 1. It is, therefore, affected by a
hardcoded credentials vulnerability:

  - A hardcoded credential vulnerability exists in a specific deployment pattern for Esri Portal for ArcGIS versions
    11.4 and below that may allow a remote authenticated attacker to gain administrative access to the system.
    (CVE-2025-2538)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://www.esri.com/arcgis-blog/products/trust-arcgis/administration/portal-for-arcgis-security-2025-update-1-patch
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?840743b1");
  script_set_attribute(attribute:"solution", value:
"Apply the Security 2025 Update 1 patch Esri Portal for ArcGIS.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-2538");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/03/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:esri:portal_for_arcgis");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("esri_portal_for_arcgis_win_installed.nbin");
  script_require_keys("installed_sw/Esri Portal for ArcGIS");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Esri Portal for ArcGIS', win_local:TRUE);

if ('Security 2025 Update 1' >< app_info['Security Patches'])
  vcf::audit(app_info);

var constraints = [
  { 'equal' : '10.9.1', 'fixed_display' : '10.9.1 Security 2025 Update 1' },
  { 'equal' : '11.1', 'fixed_display' : '11.1 Security 2025 Update 1' },
  { 'equal' : '11.2', 'fixed_display' : '11.2 Security 2025 Update 1' },
  { 'equal' : '11.3', 'fixed_display' : '11.3 Security 2025 Update 1' },
  { 'equal' : '11.4', 'fixed_display' : '11.4 Security 2025 Update 1' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
