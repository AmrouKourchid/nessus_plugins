#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(233816);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/04");

  script_cve_id("CVE-2025-22231");
  script_xref(name:"VMSA", value:"2025-0006");
  script_xref(name:"IAVA", value:"2025-A-0216");

  script_name(english:"VMware Aria Operations 8.x < 8.18 HF 5 Privilege Escalation (VMSA-2025-0006)");

  script_set_attribute(attribute:"synopsis", value:
"VMware Aria Operations running on the remote host is affected by a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of VMware Aria Operations (formerly vRealize Operations) running on the remote host is 8.x prior to 8.18
HF 5. It is, therefore, affected by a privilege escalation vulnerability. A malicious actor with local administrative
privileges can escalate their privileges to root on the appliance running VMware Aria Operations.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2025-0006.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware Aria Operations version 8.18 HF 5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-22231");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/04/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vrealize_operations");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_vrealize_operations_manager_webui_detect.nbin");
  script_require_keys("installed_sw/vRealize Operations Manager");
  script_require_ports("Services/www", 443);

  exit(0);
}

include('vcf.inc');
include('http.inc');

var app = 'vRealize Operations Manager';
get_install_count(app_name:app, exit_if_zero:TRUE);

var port = get_http_port(default:443);

var app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);

var constraints = [
  {'min_version':'8.0', 'fixed_version':'8.18.3.24663027', 'fixed_display': '8.18 HF 5 (8.18.3.24663027)'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
