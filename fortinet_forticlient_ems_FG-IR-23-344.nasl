#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(234214);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/11");

  script_cve_id("CVE-2025-22855");
  script_xref(name:"IAVA", value:"2025-A-0253");

  script_name(english:"Fortinet FortiClient EMS 7.2.x / 7.4.x < 7.4.3 XSS (FG-IR-23-344)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of Fortinet FortiClient EMS installed on the remote host is 7.2.1 through 7.2.9 or 7.4.x prior to
7.4.3. It is, therefore, affected by a vulnerability as referenced in the FG-IR-23-344 advisory:

  - An improper neutralization of input during web page generation ('Cross-site Scripting') [CWE-79] vulnerability in
    Fortinet FortiClient before 7.4.1 may allow the EMS administrator to send messages containing javascript code.
    (CVE-2025-22855)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.fortiguard.com/psirt/FG-IR-23-344");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Fortinet FortiClient EMS version 7.4.3 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-22855");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/04/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/11");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:fortinet:forticlient_enterprise_management_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("fortinet_forticlient_ems_win_installed.nbin", "fortinet_forticlient_ems_web_detect.nbin");
  script_require_keys("installed_sw/Fortinet FortiClient EMS");

  exit(0);
}

include('vdf.inc');

# @tvdl-content
var vuln_data = {
  'metadata': {'spec_version': '1.0'},
  'checks': [
    {
      'product': {'name': 'Fortinet FortiClient EMS', 'type': 'app'},
      'check_algorithm': 'default',
      'constraints': [
        {'min_version':'7.2.1','max_version':'7.2.9','fixed_display': '7.4.3'},
        {'min_version':'7.4.0','max_version':'7.4.1','fixed_display': '7.4.3'}
      ]
    }
  ]
};

var result = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_WARNING, flags:{'xss':TRUE});
vdf::handle_check_and_report_errors(vdf_result:result);
