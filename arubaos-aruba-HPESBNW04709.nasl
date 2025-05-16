#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(207739);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/27");

  script_cve_id("CVE-2024-42501", "CVE-2024-42502", "CVE-2024-42503");
  script_xref(name:"IAVA", value:"2024-A-0590");

  script_name(english:"ArubaOS 8.10.x < 8.10.0.14, 8.12.x < 8.12.0.2, 10.6.x < 10.6.0.3 Multiple Vulnerabilities (HPESBNW04709)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of ArubaOS installed on the remote host is affected by multiple vulnerabilities:

  - An authenticated Path Traversal vulnerabilities exists in the ArubaOS. Successful exploitation of this 
    vulnerability allows an attacker to install unsigned packages on the underlying operating system, enabling the 
    threat actor to execute arbitrary code or install implants. (CVE-2024-42501) 

  - Authenticated command injection vulnerability exists in the ArubaOS command line interface. Successful 
    exploitation of this vulnerability result in the ability to inject shell commands on the underlying operating 
    system. (CVE-2024-42502) 

  - Authenticated command execution vulnerability exist in the ArubaOS command line interface (CLI). Successful 
    exploitation of this vulnerabilities result in the ability to run arbitrary commands as a priviledge user on the 
    underlying operating system. (CVE-2024-42503)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://support.hpe.com/hpesc/public/docDisplay?docId=hpesbnw04709en_us&docLocale=en_US
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?37893317");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the ArubaOS version mentioned in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-42501");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-42503");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/09/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/25");

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
  { 'min_version' : '8.10', 'fixed_version' : '8.10.0.14' },
  { 'min_version' : '8.12', 'fixed_version' : '8.12.0.2'},
  { 'min_version' : '10.6', 'fixed_version' : '10.6.0.3' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
