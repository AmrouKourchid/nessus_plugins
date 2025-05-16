#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(194952);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/07");

  script_cve_id(
    "CVE-2024-26304",
    "CVE-2024-26305",
    "CVE-2024-33511",
    "CVE-2024-33512",
    "CVE-2024-33513",
    "CVE-2024-33514",
    "CVE-2024-33515",
    "CVE-2024-33516",
    "CVE-2024-33517",
    "CVE-2024-33518"
  );
  script_xref(name:"IAVA", value:"2024-A-0269-S");

  script_name(english:"ArubaOS 8.10.x, 8.11.x, 10.4.x 10.5.x Multiple Vulnerabilities (ARUBA-PSA-2024-004)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of ArubaOS installed on the remote host is affected by multiple vulnerabilities:

  - There are buffer overflow vulnerabilities in multiple underlying services that could lead to unauthenticated
    remote code execution by sending specially crafted packets destined to the PAPI (Aruba's access point management
    protocol) UDP port (8211). Successful exploitation of these vulnerabilities result in the ability to execute 
    arbitrary code as a privileged user on the underlying operating system. (CVE-2024-26305) 

  - There is a buffer overflow vulnerability in the underlying L2/L3 Management service that could lead to 
    unauthenticated remote code execution by sending specially crafted packets destined to the PAPI (Aruba's access 
    point management protocol) UDP port (8211). Successful exploitation of this vulnerability results in the        
    ability to execute arbitrary code as a privileged user on the underlying operating system. (CVE-2024-26304)

  - There is a buffer overflow vulnerability in the underlying Automatic Reporting service that could lead to 
    unauthenticated remote code execution by sending specially crafted packets destined to the PAPI (Aruba's access 
    point management protocol) UDP port (8211). Successful exploitation of this vulnerability results in the ability 
    to execute arbitrary code as a privileged user on the underlying operating system. (CVE-2024-33511)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.arubanetworks.com/assets/alert/ARUBA-PSA-2024-004.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the ArubaOS version mentioned in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-26305");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-33512");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/03");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:arubanetworks:arubaos");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:arubaos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("arubaos_installed.nbin", "arubaos_detect.nbin");
  script_require_keys("installed_sw/ArubaOS");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::aruba::combined_get_app_info(os_flavour:'ArubaOS');
if (!empty_or_null(app_info.ver_model))
    audit(AUDIT_INST_VER_NOT_VULN, 'ArubaOS', app_info.version);

var constraints = [
  { 'min_version' : '8.10', 'fixed_version' : '8.10.0.11'},  
  { 'min_version' : '8.11', 'fixed_version' : '8.11.2.2'},
  { 'min_version' : '10.4', 'fixed_version' : '10.4.1.1' },
  { 'min_version' : '10.5', 'fixed_version' : '10.5.1.1'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
