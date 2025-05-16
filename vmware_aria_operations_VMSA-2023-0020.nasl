#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(182186);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/23");

  script_cve_id("CVE-2023-34043");
  script_xref(name:"VMSA", value:"2023-0020");
  script_xref(name:"IAVA", value:"2023-A-0508-S");

  script_name(english:"VMware Aria Operations < 8.6 Hot Fix 11 / 8.10 Hot Fix 9 / 8.12 Hot Fix 5 Privilege Escalation (VMSA-2023-0020)");

  script_set_attribute(attribute:"synopsis", value:
"VMware Aria Operations running on the remote host is affected by a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of VMware Aria Operations (formerly vRealize Operations) running on the remote host is 8.6.x prior to
8.6 Hot Fix 11, 8.10.x prior to 8.10 Hot Fix 9 or 8.12.x prior to 8.12 Hot Fix 5. It is, therefore, affected by a
privilege escalation vulnerability. An attacker with administrative access on the local system can escalate privileges
to 'root'.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2023-0020.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware Aria Operations version 8.6 Hot Fix 11, 8.10 Hot Fix 9, 8.12 Hot Fix 5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-34043");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/09/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/09/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vrealize_operations");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  {'min_version':'8.6.0', 'fixed_version':'8.6.4.22338372', 'fixed_display': '8.6 Hot Fix 11 (8.6.4.22338372)'},
  {'min_version':'8.10.0', 'fixed_version':'8.10.2.22335859', 'fixed_display': '8.10 Hot Fix 9 (8.10.2.22335859)'},
  {'min_version':'8.12.0', 'fixed_version':'8.12.1.22482700', 'fixed_display': '8.12 Hot Fix 5 (8.12.1.22482700)'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
