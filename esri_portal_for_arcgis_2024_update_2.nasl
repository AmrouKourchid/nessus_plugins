#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(208442);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/03");

  script_cve_id(
    "CVE-2024-25691",
    "CVE-2024-25694",
    "CVE-2024-25701",
    "CVE-2024-25702",
    "CVE-2024-25707",
    "CVE-2024-38036",
    "CVE-2024-38037",
    "CVE-2024-38038",
    "CVE-2024-38039",
    "CVE-2024-38040",
    "CVE-2024-8148",
    "CVE-2024-8149"
  );
  script_xref(name:"IAVB", value:"2024-B-0149-S");

  script_name(english:"Esri Portal for ArcGIS < Security 2024 Update 2 Multiple Vulnerabilities (10.8.1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The version of Esri Portal for ArcGIS installed is missing Security 2024 Update 2. It is, therefore, affected by
multiple vulnerabilities including:

  - There is a local file inclusion vulnerability in Esri Portal for ArcGIS 11.2. 11.1, 11.0 and 10.9.1 that may allow 
    a remote, unauthenticated attacker to craft a URL that could potentially disclose sensitive 
    configuration information by reading internal files. (CVE-2024-38040)

  - There is a reflected XSS vulnerability in Esri Portal for ArcGIS versions 10.9.1, 10.8.1 and 10.7.1 which may 
    allow a remote, unauthenticated attacker to create a crafted link which when clicked could potentially execute 
    arbitrary JavaScript code in the victim’s browser. (CVE-2024-38038)

  - There is a reflected XSS vulnerability in Esri Portal for ArcGIS versions 11.1, 10.9.1 and 10.8.1 which may 
    allow a remote, unauthenticated attacker to create a crafted link which when clicked could potentially 
    execute arbitrary JavaScript code in the victim’s browser. (CVE-2024-25691)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://www.esri.com/arcgis-blog/products/trust-arcgis/administration/portal-for-arcgis-security-2024-update-2-released/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f0d2b7b0");
  script_set_attribute(attribute:"solution", value:
"Apply the Security 2024 Update 2 patch Esri Portal for ArcGIS.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-38040");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/08/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/09");

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

if ('Security 2024 Update 2' >< app_info['Security Patches'])
  vcf::audit(app_info);

var constraints = [
  { 'equal' : '10.8.1', 'fixed_display' : '10.8.1 Security 2024 Update 2' },
  { 'equal' : '10.9.1', 'fixed_display' : '10.9.1 Security 2024 Update 2' },
  { 'equal' : '11.1', 'fixed_display' : '11.1 Security 2024 Update 2' },
  { 'equal' : '11.2', 'fixed_display' : '11.2 Security 2024 Update 2' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE,
    flags:{'xss':TRUE, 'xsrf':TRUE}
);

