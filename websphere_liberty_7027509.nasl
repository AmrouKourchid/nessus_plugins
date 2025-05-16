#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(182678);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/26");

  script_cve_id("CVE-2023-38737");
  script_xref(name:"IAVA", value:"2023-A-0520-S");
  script_xref(name:"IAVA", value:"2023-A-0589-S");

  script_name(english:"IBM WebSphere Application Server Liberty 22.0.0.13 < 23.0.0.8 DoS (7027509)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web application server is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"IBM WebSphere Application Server Liberty 22.0.0.13 through 23.0.0.7 is vulnerable to a denial of service, caused by
sending a specially-crafted request. A remote attacker could exploit this vulnerability to cause the server to consume
memory resources.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/7027509");
  script_set_attribute(attribute:"see_also", value:"https://exchange.xforce.ibmcloud.com/vulnerabilities/262567");
  script_set_attribute(attribute:"solution", value:
"Update to IBM WebSphere Application Server Liberty version 23.0.0.8 or later. Alternatively, upgrade to the minimal
fix pack levels required by the interim fix and then apply Interim Fix PH56004.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-38737");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/08/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/08/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/06");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_application_server");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("websphere_liberty_detect.nbin", "ibm_websphere_application_server_liberty_nix_installed.nbin");
  script_require_keys("installed_sw/IBM WebSphere Application Server");

  exit(0);
}


include('vcf.inc');
include('http.inc');

var app = 'IBM WebSphere Application Server';
var fix = 'Interim Fix PH56004';

var app_info = vcf::combined_get_app_info(app:app);
vcf::check_granularity(app_info:app_info, sig_segments:4);

if (app_info['Product'] != app + ' Liberty')
  audit(AUDIT_HOST_NOT, app + ' Liberty');

# If the detection is only remote, Source will be set, and we should require paranoia
if (!empty_or_null(app_info['Source']) && app_info['Source'] != 'unknown' && report_paranoia < 2)
  audit(AUDIT_POTENTIAL_VULN, app);

var constraints = [
 { 'min_version' : '22.0.0.13', 'fixed_version' : '23.0.0.8', 'fixed_display' : '23.0.0.8 or ' + fix }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
