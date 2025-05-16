#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(175134);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/23");

  script_cve_id("CVE-2022-39161");
  script_xref(name:"IAVA", value:"2023-A-0227");

  script_name(english:"IBM WebSphere Application Server 8.5.0.0 < 8.5.5.24, 9.0.0.0 < 9.0.5.16 MitM (6987779)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web application server is affected by a man-in-the-middle vulnerability.");
  script_set_attribute(attribute:"description", value:
"The IBM WebSphere Application Server running on the remote host is affected by a man-in-the-middle vulnerability.
IBM WebSphere Application Server 8.5 and 9.0, when configured to communicate with the Web Server Plug-ins for IBM 
WebSphere Application Server, could allow an authenticated user to conduct spoofing attacks. A man-in-the-middle 
attacker could exploit this vulnerability using using a certificate issued by a trusted authority to obtain sensitive 
information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/6987779");
  script_set_attribute(attribute:"solution", value:
"Update to IBM WebSphere Application Server versions 8.5.5.24, 9.0.5.16 or later or apply Interim Fix PH48747.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-39161");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/05");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_application_server");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("websphere_detect.nasl", "ibm_enum_products.nbin", "ibm_websphere_application_server_nix_installed.nbin", "ibm_websphere_application_server_win_installed.nbin");
  script_require_keys("installed_sw/IBM WebSphere Application Server");

  exit(0);
}

include('vcf.inc');

var app = 'IBM WebSphere Application Server';
var app_im = 'IBM Installation Manager';

get_install_count(app_name:app, app_name:app_im, exit_if_zero:TRUE);

var app_info = vcf::combined_get_app_info(app:app);
var app_info_im = vcf::combined_get_app_info(app:app_im);
vcf::check_granularity(app_info:app_info, sig_segments:4);

var fix = 'Interim Fix PH48747';
var fixes = app_info['Fixes'];

if ('PH48747' >< fixes)
  audit(AUDIT_INST_VER_NOT_VULN, app);

var require_paranoia = FALSE;
# If the detection is only remote, Source will be set, and we should require paranoia for versions with a fix
if (!empty_or_null(app_info['Source']) && app_info['Source'] != 'unknown')
    require_paranoia = TRUE;

var constraints = [
  { 'min_version' : '9.0.0.0', 'fixed_version' : '9.0.5.16', 'fixed_display' : '9.0.5.16 or ' + fix },
  { 'min_version' : '8.5.0.0', 'fixed_version' : '8.5.5.24', 'fixed_display' : '8.5.5.24 or ' + fix }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, require_paranoia:require_paranoia, severity:SECURITY_WARNING);
