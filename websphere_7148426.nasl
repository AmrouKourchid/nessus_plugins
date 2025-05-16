#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(193372);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/23");

  script_cve_id("CVE-2024-22354");

  script_name(english:"IBM WebSphere Application Server 8.5.x < 8.5.5.26 / 9.x < 9.0.5.20 / Liberty 17.0.0.3 < 24.0.0.6 (7148426)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web application server is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of IBM WebSphere Application Server running on the remote host is affected by a vulnerability as referenced
in the 7148426 advisory.

  - IBM WebSphere Application Server 8.5, 9.0 and IBM WebSphere Application Server Liberty 17.0.0.3 through
    24.0.0.5 are vulnerable to an XML External Entity Injection (XXE) attack when processing XML data. A
    remote attacker could exploit this vulnerability to expose sensitive information, consume memory
    resources, or to conduct a server-side request forgery attack. IBM X-Force ID: 280401. (CVE-2024-22354)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.

Further note that the vendor removed the original Interim Fix, PH59682, and replaced it with the following :

  - Interim Fix PH61042 for IBM WebSphere Application Server Liberty
  - Interim Fix PH58869 for IBM WebSphere Application Server");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/7148426");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/7148359");
  script_set_attribute(attribute:"solution", value:
"Update to IBM WebSphere Application Server version 8.5.5.26, 9.0.5.20, 24.0.0.6 Liberty or later. Alternatively, upgrade
to the minimal fix pack levels required by the interim fix and then apply Interim Fix PH61042 or PH58869 depending on affected product.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-22354");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/16");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_application_server");
  script_set_attribute(attribute:"generated_plugin", value:"former");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("websphere_detect.nasl", "ibm_enum_products.nbin", "ibm_websphere_application_server_nix_installed.nbin", "ibm_websphere_application_server_win_installed.nbin");
  script_require_keys("installed_sw/IBM WebSphere Application Server");

  exit(0);
}

include('vcf.inc');

var app = 'IBM WebSphere Application Server';
var app_info = vcf::combined_get_app_info(app:app);
vcf::check_granularity(app_info:app_info, sig_segments:4);

# If the detection is only remote, Source will be set, and we should require paranoia
var require_paranoid = FALSE;
if (!empty_or_null(app_info['Source']) && app_info['Source'] != 'unknown' && report_paranoia < 2)
  require_paranoid = TRUE;

if ('PH58869' >< app_info['Fixes'] ||
    'PH61042' >< app_info['Fixes'])
  audit(AUDIT_INST_VER_NOT_VULN, app);

var constraints = [
  { 'min_version' : '8.5.0.0', 'fixed_version' : '8.5.5.26', 'fixed_display' : '8.5.5.26 or Interim Fix PH58869' },
  { 'min_version' : '9.0.0.0', 'fixed_version' : '9.0.5.20', 'fixed_display' : '9.0.5.20 or Interim Fix PH58869' },
  { 'min_version' : '17.0.0.3', 'fixed_version' : '24.0.0.6', 'fixed_display' : '24.0.0.6 or Interim Fix PH61042' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    require_paranoia:require_paranoid,
    severity:SECURITY_WARNING
);
