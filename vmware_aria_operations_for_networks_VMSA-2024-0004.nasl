#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(190887);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/13");

  script_cve_id("CVE-2024-22235");
  script_xref(name:"VMSA", value:"2024-0004");
  script_xref(name:"IAVA", value:"2024-A-0109-S");

  script_name(english:"VMWare Aria Operations < 8.16 PrivEsc (VMSA-2024-0004)");

  script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote server is affected by a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the instance of VMWare Aria Operations (formerly vRealize Operations) running on the remote web
server is < 8.16.0.23251571. It is, therefore, affected by the following:

  - VMware Aria Operations contains a local privilege escalation vulnerability. A malicious actor with administrative 
    access to the local system can escalate privileges to 'root'. 
  
Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.vmware.com/security/advisories/VMSA-2024-0004.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4b75b4b7");
  script_set_attribute(attribute:"see_also", value:"https://kb.vmware.com/s/article/92148");
  # https://docs.vmware.com/en/VMware-Aria-Operations/8.16/rn/vmware-aria-operations-816-release-notes/index.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?316a78f9");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMWare Aria Operations 8.16.0.1706185032 or later, or follow the steps in KB 92148.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-22235");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vrealize_operations");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  {'min_version':'4.0', 'fixed_version':'8.16.0.23251571'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
