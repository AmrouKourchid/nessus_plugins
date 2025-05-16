#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(193182);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/03");

  script_cve_id(
    "CVE-2024-25690",
    "CVE-2024-25692",
    "CVE-2024-25693",
    "CVE-2024-25695",
    "CVE-2024-25696",
    "CVE-2024-25697",
    "CVE-2024-25698",
    "CVE-2024-25699",
    "CVE-2024-25700",
    "CVE-2024-25703",
    "CVE-2024-25704",
    "CVE-2024-25705",
    "CVE-2024-25706",
    "CVE-2024-25708",
    "CVE-2024-25709"
  );
  script_xref(name:"IAVA", value:"2024-A-0203-S");

  script_name(english:"Esri Portal for ArcGIS < Security 2024 Update 1 Multiple Vulnerabilities (10.8.1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The version of Esri Portal for ArcGIS installed is missing Security 2024 Update 1. It is, therefore, affected by
multiple vulnerabilities including:

  - There is a difficult to exploit improper authentication issue in the Home application for Esri Portal for
    ArcGIS versions 10.8.1 through 11.2 on Windows and Linux, and ArcGIS Enterprise 11.1 and below on
    Kubernetes which, under unique circumstances, could potentially allow a remote, unauthenticated attacker
    to compromise the confidentiality, integrity, and availability of the software. (CVE-2024-25699)

  - There is a cross-site-request forgery vulnerability in Esri Portal for ArcGIS Versions 11.1 and below that
    may in some cases allow a remote, unauthenticated attacker to trick an authorized user into executing
    unwanted actions via a crafted form. The impact to Confidentiality and Integrity vectors is limited and of
    low severity. (CVE-2024-25692)

  - There is a Cross-site Scripting vulnerability in Portal for ArcGIS in versions <= 11.2 that may allow a
    remote, authenticated attacker to provide input that is not sanitized properly and is rendered in error
    messages. The are no privileges required to execute this attack. (CVE-2024-25695)

  - There is a path traversal in Esri Portal for ArcGIS versions <= 11.2. Successful exploitation may allow a
    remote, authenticated attacker to traverse the file system to access files or execute code outside of the
    intended directory. (CVE-2024-25693)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://www.esri.com/arcgis-blog/products/arcgis-enterprise/administration/portal-for-arcgis-security-2024-update-2/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cfb9f741");
  script_set_attribute(attribute:"solution", value:
"Apply the Security 2024 Update 1 patch Esri Portal for ArcGIS.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-25693");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:esri:portal_for_arcgis");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("esri_portal_for_arcgis_win_installed.nbin");
  script_require_keys("installed_sw/Esri Portal for ArcGIS");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Esri Portal for ArcGIS', win_local:TRUE);

if ('Security 2024 Update 1' >< app_info['Security Patches'])
  vcf::audit(app_info);

var constraints = [
  { 'equal' : '10.8.1', 'fixed_display' : '10.8.1 Security 2024 Update 1' },
  { 'equal' : '10.9.1', 'fixed_display' : '10.9.1 Security 2024 Update 1' },
  { 'equal' : '11.0', 'fixed_display' : '11.0 Security 2024 Update 1' },
  { 'equal' : '11.1', 'fixed_display' : '11.1 Security 2024 Update 1' },
  { 'equal' : '11.2', 'fixed_display' : '11.2 Security 2024 Update 1' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE,
    flags:{'xss':TRUE, 'xsrf':TRUE}
);

