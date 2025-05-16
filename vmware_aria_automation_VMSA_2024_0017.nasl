#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(202622);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/19");

  script_cve_id("CVE-2024-22280");
  script_xref(name:"VMSA", value:"2024-0017");
  script_xref(name:"IAVA", value:"2024-A-0434");

  script_name(english:"VMware Aria Automation SQLi Vulnerability (VMSA-2024-0017)");

  script_set_attribute(attribute:"synopsis", value:
"A device management application running on the remote host is affected
by an access control vulnerability.");
  script_set_attribute(attribute:"description", value:
"The VMware Aria Automation application running on the remote host is affected by a SQL injection vulnerability due to 
incorrect input validation which allows for SQL-injection in the product. An authenticated malicious actor may exploit 
this vulnerability leading to unauthorized access to remote organizations and workflows.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/24598
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e3dcb09a");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware Aria Automation version 8.17.0 or later or apply the appropriate patch as advised 
in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-22280");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/18");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vrealize_automation");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "vmware_vrealize_automation_webui_detect.nbin");
  script_require_ports("Host/VMware vRealize Automation/Version", "installed_sw/VMware vRealize Automation");

  exit(0);
}

include('misc_func.inc');
include('http_func.inc');
include('webapp_func.inc');
include('vcf.inc');
include('vcf_extras.inc');


var app_name = 'VMware vRealize Automation';

var app_info = vcf::vmware_aria_auto::get_app_info(app:app_name);

var constraints = [
  { 'min_version' : '8.13.0.0', 'fixed_version' : '8.13.0.31771', 'fixed_display': '8.13.0 Build 31771'},
  { 'min_version' : '8.13.1.0', 'fixed_version' : '8.13.1.32402', 'fixed_display': '8.13.1 Build 32402'},
  { 'min_version' : '8.14.0.0', 'fixed_version' : '8.14.0.33093', 'fixed_display': '8.14.0 Build 33093'},
  { 'min_version' : '8.14.1.0', 'fixed_version' : '8.14.1.33514', 'fixed_display': '8.14.1 Build 33514'},
  { 'min_version' : '8.16.0.0', 'fixed_version' : '8.16.0.33723', 'fixed_display': '8.16.0 Build 33723'},
  { 'min_version' : '8.16.1.0', 'fixed_version' : '8.16.1.34318', 'fixed_display': '8.16.1 Build 34318'},
  { 'min_version' : '8.16.2.0', 'fixed_version' : '8.16.2.34729', 'fixed_display': '8.16.2 Build 34729'},
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);


