#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(178469);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/10/20");

  script_cve_id(
    "CVE-2023-0464",
    "CVE-2023-22016",
    "CVE-2023-22017",
    "CVE-2023-22018"
  );
  script_xref(name:"IAVA", value:"2023-A-0371-S");

  script_name(english:"Oracle VM VirtualBox < 6.1.46 / 7.x < 7.0.10 (July 2023 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of VirtualBox installed on the remote host is prior to 6.1.46 or 7.0.10. It is, therefore, affected by 
multiple vulnerabilities as referenced in the July 2023 CPU advisory:

  - Vulnerability in the Oracle VM VirtualBox product of Oracle Virtualization (component: Core). Supported
  versions that are affected are Prior to 6.1.46 and Prior to 7.0.10. Difficult to exploit vulnerability
  allows unauthenticated attacker with network access via RDP to compromise Oracle VM VirtualBox. Successful
  attacks of this vulnerability can result in takeover of Oracle VM VirtualBox. (CVE-2023-22018)

  - Vulnerability in the Oracle VM VirtualBox product of Oracle Virtualization (component: Core (OpenSSL)). 
  Supported versions that are affected are Prior to 6.1.46 and Prior to 7.0.10. Easily exploitable
  vulnerability allows unauthenticated attacker with network access via TLS to compromise Oracle VM VirtualBox
  . Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently
  repeatable crash (complete DOS) of Oracle VM VirtualBox. (CVE-2023-0464)

  - Vulnerability in the Oracle VM VirtualBox product of Oracle Virtualization (component: Core). Supported
  versions that are affected are Prior to 6.1.46 and Prior to 7.0.10. Easily exploitable vulnerability allows
  low privileged attacker with logon to the infrastructure where Oracle VM VirtualBox executes to compromise
  Oracle VM VirtualBox. Successful attacks of this vulnerability can result in unauthorized ability to cause
  a hang or frequently repeatable crash (complete DOS) of Oracle VM VirtualBox. Note: This vulnerability
  applies to Windows VMs only. (CVE-2023-22017)
  
Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://www.oracle.com/docs/tech/security-alerts/cpujul2023cvrf.xml
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3d5c86d3");
  # https://www.oracle.com/security-alerts/cpujul2023.html#AppendixOVIR
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1b8f061e");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2023 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-22018");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/07/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:vm_virtualbox");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  { 'min_version' : '0.0', 'fixed_version' : '6.1.46'},
  { 'min_version' : '7.0', 'fixed_version' : '7.0.10' },
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);