#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(136897);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/23");

  script_cve_id("CVE-2018-1793");

  script_name(english:"IBM WebSphere Application Server 7.0.0.0 <= 7.0.0.45 / 8.0.0.0 <= 8.0.0.15 / 8.5.0.0 <= 8.5.5.14 / 9.0.0.0 <= 9.0.0.9 XSS");

  script_set_attribute(attribute:"synopsis", value:
"The remote web application server is affected by a cross-site scripting vulnerability");
  script_set_attribute(attribute:"description", value:
"A cross-site scripting (XSS) vulnerability exists in WebSphere Application Server
due to improper validation of user-supplied input before returning it to users.
An authenticated, remote attacker can exploit this, by convincing a user
to click a specially crafted URL, to execute arbitrary script code in a user's browser session.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/729563");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM WebSphere Application Server version recommended in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-1793");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/27");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_application_server");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("websphere_detect.nasl", "ibm_enum_products.nbin", "ibm_websphere_application_server_nix_installed.nbin");
  script_require_keys("installed_sw/IBM WebSphere Application Server");

  exit(0);
}

include('vcf.inc');


app = 'IBM WebSphere Application Server';
fix = 'Interim Fix PH01752';

get_install_count(app_name:app, exit_if_zero:TRUE);
app_info = vcf::combined_get_app_info(app:app);
vcf::check_granularity(app_info:app_info, sig_segments:4);

# If the detection is only remote, Source will be set, and we should require paranoia
if (!empty_or_null(app_info['Source']) && app_info['Source'] != 'unknown' && report_paranoia < 2)
  audit(AUDIT_PARANOID);

if ('PH01752' >< app_info['Fixes'])
  audit(AUDIT_INST_VER_NOT_VULN, app);

constraints = [
  {'min_version':'7.0.0.0', 'max_version':'7.0.0.45', 'fixed_display':'7.0.0.45 ' + fix},
  {'min_version':'8.0.0.0', 'max_version':'8.0.0.15', 'fixed_display':'8.0.0.15 ' + fix},
  {'min_version':'8.5.0.0', 'max_version':'8.5.5.14', 'fixed_display':'8.5.5.14 ' + fix + ' or 8.5.5.15'},
  {'min_version':'9.0.0.0', 'max_version':'9.0.0.9', 'fixed_display':'9.0.0.9 ' + fix + ' or 9.0.0.10'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
