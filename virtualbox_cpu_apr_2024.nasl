#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(193427);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/09");

  script_cve_id(
    "CVE-2024-21103",
    "CVE-2024-21106",
    "CVE-2024-21107",
    "CVE-2024-21108",
    "CVE-2024-21109",
    "CVE-2024-21110",
    "CVE-2024-21111",
    "CVE-2024-21112",
    "CVE-2024-21113",
    "CVE-2024-21114",
    "CVE-2024-21115",
    "CVE-2024-21116",
    "CVE-2024-21121"
  );
  script_xref(name:"IAVA", value:"2024-A-0246");

  script_name(english:"Oracle VM VirtualBox (April 2024 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The 7.0.16 versions of VM VirtualBox installed on the remote host are affected by multiple vulnerabilities as referenced
in the April 2024 CPU advisory:

  - Vulnerability in the Oracle VM VirtualBox product of Oracle Virtualization (component: Core). Supported versions 
    that are affected are Prior to 7.0.16. Easily exploitable vulnerability allows low privileged attacker with logon 
    to the infrastructure where Oracle VM VirtualBox executes to compromise Oracle VM VirtualBox. While the 
    vulnerability is in Oracle VM VirtualBox, attacks may significantly impact additional products (scope change). 
    Successful attacks of this vulnerability can result in takeover of Oracle VM VirtualBox. (CVE-2024-21112)

  - Vulnerability in the Oracle VM VirtualBox product of Oracle Virtualization (component: Core). Supported versions 
    that are affected are Prior to 7.0.16. Easily exploitable vulnerability allows low privileged attacker with logon 
    to the infrastructure where Oracle VM VirtualBox executes to compromise Oracle VM VirtualBox. While the 
    vulnerability is in Oracle VM VirtualBox, attacks may significantly impact additional products (scope change). 
    Successful attacks of this vulnerability can result in takeover of Oracle VM VirtualBox. (CVE-2024-21113)

  - Vulnerability in the Oracle VM VirtualBox product of Oracle Virtualization (component: Core). Supported versions
    that are affected are Prior to 7.0.16. Easily exploitable vulnerability allows low privileged attacker with logon
    to the infrastructure where Oracle VM VirtualBox executes to compromise Oracle VM VirtualBox. While the
    vulnerability is in Oracle VM VirtualBox, attacks may significantly impact additional products (scope change).
    Successful attacks of this vulnerability can result in takeover of Oracle VM VirtualBox. (CVE-2024-21114)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpuapr2024csaf.json");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuapr2024.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2024 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-21114");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-21115");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:vm_virtualbox");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("virtualbox_installed.nasl", "macosx_virtualbox_installed.nbin");
  script_require_ports("installed_sw/Oracle VM VirtualBox", "installed_sw/VirtualBox");

  exit(0);
}

include('vcf.inc');

var app_info = NULL;
if (get_kb_item('installed_sw/Oracle VM VirtualBox'))
  app_info = vcf::get_app_info(app:'Oracle VM VirtualBox', win_local:TRUE);
else
  app_info = vcf::get_app_info(app:'VirtualBox');

var constraints = [
  { 'min_version' : '7.0', 'fixed_version' : '7.0.16' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
