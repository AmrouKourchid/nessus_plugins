#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(214277);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/23");

  script_cve_id("CVE-2025-22215");
  script_xref(name:"VMSA", value:"2025-0001");
  script_xref(name:"IAVA", value:"2025-A-0012");

  script_name(english:"VMware Aria Automation SSRF (VMSA-2025-0001)");

  script_set_attribute(attribute:"synopsis", value:
"A device management application running on the remote host is affected
by a server side request forgery vulnerability.");
  script_set_attribute(attribute:"description", value:
"The VMware Aria Automation application running on the remote host is affected by a vulnerability as referenced in
the VMSA-2025-0001 advisory.

    - VMware Aria Automation contains a server-side request forgery (SSRF) vulnerability. A malicious actor 
      with 'Organization Member' access to Aria Automation may exploit this vulnerability enumerate internal 
      services running on the host/network. (CVE-2025-22215)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/25312
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?543fd727");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware Aria Automation version 8.18.1 patch 1 or later or apply the appropriate patch as advised 
in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-22215");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/01/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/01/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/16");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vrealize_automation");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  { 'fixed_version' : '8.18.1.36856', 'fixed_display': '8.18.1 Build 36856'},
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
