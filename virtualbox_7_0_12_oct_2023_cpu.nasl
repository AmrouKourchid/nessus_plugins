#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(183313);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/09");

  script_cve_id("CVE-2023-22098", "CVE-2023-22099", "CVE-2023-22100");
  script_xref(name:"IAVA", value:"2023-A-0564-S");

  script_name(english:"Oracle VM VirtualBox Multiple Vulnerabilities (October 2023 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of VirtualBox installed on the remote host is affected by multiple vulnerabilities as referenced 
in the October 2023 CPU advisory:

  - Vulnerability in the Oracle VM VirtualBox product of Oracle Virtualization (component: Core). Supported 
    versions that are affected are Prior to 7.0.12. Easily exploitable vulnerability allows high privileged 
    attacker with logon to the infrastructure where Oracle VM VirtualBox executes to compromise Oracle VM 
    VirtualBox. While the vulnerability is in Oracle VM VirtualBox, attacks may significantly impact 
    additional products (scope change). Successful attacks of this vulnerability can result in unauthorized 
    ability to cause a hang or frequently repeatable crash (complete DOS) of Oracle VM VirtualBox as well as 
    unauthorized update, insert or delete access to some of Oracle VM VirtualBox accessible data and 
    unauthorized read access to a subset of Oracle VM VirtualBox accessible data. 
    (CVE-2023-22098, CVE-2023-22099)

  - Vulnerability in the Oracle VM VirtualBox product of Oracle Virtualization (component: Core). Supported 
    versions that are affected are Prior to 7.0.12. Easily exploitable vulnerability allows high privileged 
    attacker with logon to the infrastructure where Oracle VM VirtualBox executes to compromise Oracle VM 
    VirtualBox. While the vulnerability is in Oracle VM VirtualBox, attacks may significantly impact additional 
    products (scope change). Successful attacks of this vulnerability can result in unauthorized access to 
    critical data or complete access to all Oracle VM VirtualBox accessible data and unauthorized ability to 
    cause a hang or frequently repeatable crash (complete DOS) of Oracle VM VirtualBox. (CVE-2023-22100)
  
Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpuoct2023cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://support.oracle.com/rs?type=doc&id=2978250.1");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2023 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-22099");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:vm_virtualbox");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

var constraints = [{ 'min_version' : '7.0', 'fixed_version' : '7.0.12' },];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);