#%NASL_MIN_LEVEL 80900
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(186611);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/22");

  script_cve_id("CVE-2023-20886");
  script_xref(name:"IAVA", value:"2023-A-0597");

  script_name(english:"VMware Workspace ONE UEM console Open Redirect (VMSA-2023-0025)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an open redirect vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Workspace ONE UEM console running on the remote host is 2203 prior to 22.3.0.48, 2206 prior to
22.6.0.36, 2209 prior to 22.9.0.29, 2212 prior to 22.12.0.20 or 2302 prior to 23.2.0.10. It is, therefore, affected by
an open redirect vulnerability. A remote attacker can redirect a victim to a page under the control of the attacker and
retrieve the SAML response to login as the victim user.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2023-0025.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Workspace ONE UEM console version 22.3.0.48, 22.6.0.36, 22.9.0.29, 22.12.0.12, 23.2.0.10 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20886");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/12/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:workspace_one");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_airwatch_console_detect_www.nbin");
  script_require_keys("installed_sw/AirWatch Console");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include('vcf.inc');
include('http.inc');

get_install_count(app_name:'AirWatch Console', exit_if_zero:TRUE);
var port = get_http_port(default:443);

var app_info = vcf::get_app_info(app:'AirWatch Console', port:port, webapp:TRUE);

if (app_info['Product'] != 'Workspace ONE UEM')
  audit(AUDIT_HOST_NOT, 'affected');


var constraints = [
  { 'min_version':'22.3.0.0',   'fixed_version':'22.3.0.48' },
  { 'min_version':'22.6.0.0',   'fixed_version':'22.6.0.36' },
  { 'min_version':'22.9.0.0',   'fixed_version':'22.9.0.29' },
  { 'min_version':'22.12.0.0',  'fixed_version':'22.12.0.20'},
  { 'min_version':'23.2.0.0',   'fixed_version':'23.2.0.10' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
