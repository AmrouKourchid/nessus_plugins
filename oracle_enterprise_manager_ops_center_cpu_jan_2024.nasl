#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(189241);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/18");

  script_cve_id("CVE-2023-1436");
  script_xref(name:"IAVA", value:"2024-A-0029");

  script_name(english:"Oracle Enterprise Manager Ops Center (January 2024 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a vulnerability");
  script_set_attribute(attribute:"description", value:
"The 12.4.0.0 version of Enterprise Manager Ops Center installed on the remote host is affected by a vulnerability 
as referenced in the January 2024 CPU advisory. The vulnerability lies in the Networking (Jettison)) component of
Enterprise Manager Ops Center. It is an easily exploitable vulnerability that allows unauthenticated attacker with
network access via HTTP to compromise Oracle Enterprise Manager Ops Center. Successful attacks of this vulnerability can
result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of Oracle Enterprise 
Manager Ops Center.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpujan2024csaf.json");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujan2024.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2024 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-1436");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:enterprise_manager_ops_center");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_enterprise_manager_ops_center_installed.nbin");
  script_require_keys("installed_sw/Oracle Enterprise Manager Ops Center");

  exit(0);
}

include('vcf_extras_oracle_em_ops_center.inc');

get_kb_item_or_exit('Host/local_checks_enabled');

var app_info = vcf::oracle_em_ops_center::get_app_info();
var components = get_kb_list_or_exit('installed_sw/Oracle Enterprise Manager Ops Center/*');
var installed_comp;
var vuln_comp = 0;

foreach installed_comp (keys(components))
{
  if (preg(pattern:"Enterprise Controller", string:installed_comp) || preg(pattern:"Proxy Controller", string:installed_comp))
  {
    vuln_comp = 1;
    break;
  }
}

if (vuln_comp == 1)
{
  var constraints = [ {'min_version': '12.4.0.0', 'max_version': '12.4.0.9999', 'ui_patch': '36095329'} ];
  vcf::oracle_em_ops_center::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
}
else
  audit(AUDIT_INST_PATH_NOT_VULN, app_info['app'], app_info['version'], app_info['path']);