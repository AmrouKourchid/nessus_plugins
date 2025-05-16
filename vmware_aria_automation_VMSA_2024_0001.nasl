#%NASL_MIN_LEVEL 80900
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(189244);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/26");

  script_cve_id("CVE-2023-34063");
  script_xref(name:"VMSA", value:"2024-0001");

  script_name(english:"VMware Aria Automation Access Control Vulnerability (VMSA-2024-0001)");

  script_set_attribute(attribute:"synopsis", value:
"A device management application running on the remote host is affected
by an access control vulnerability.");
  script_set_attribute(attribute:"description", value:
"The VMware Aria Automation application running on the remote host
is prior to 8.11.0 Build 30127, 8.12.0 Build 31368, 8.13.0 Build 32385, 8.14.1 Build 33501, or 8.16.0.
It is, therefore, affected by a missing access control vulnerability. An authenticated malicious 
actor may exploit this vulnerability leading to unauthorized access to remote organizations and workflows.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2024-0001.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware Aria Automation version 8.16 or later or apply the appropriate patch as advised 
in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-34063");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/19");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vrealize_automation");
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
  { 'min_version' : '4.0', 'max_version' : '8.11', 'fixed_display': 'Upgrade to 8.16 or later'},
  { 'min_version' : '8.11.0.0', 'fixed_version' : '8.11.2.30127', 'fixed_display': '8.11.0 Build 30127'},
  { 'min_version' : '8.12.0.0', 'fixed_version' : '8.12.2.31368', 'fixed_display': '8.12.0 Build 31368'},
  { 'min_version' : '8.13.0.0', 'fixed_version' : '8.13.1.32385', 'fixed_display': '8.13.0 Build 32385'},
  { 'min_version' : '8.14.0.0', 'fixed_version' : '8.14.1.33501', 'fixed_display': '8.14.1 Build 33501'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);


