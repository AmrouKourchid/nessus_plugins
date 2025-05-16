##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(178709);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/10/24");

  script_cve_id("CVE-2023-20860", "CVE-2023-20861", "CVE-2023-24998");
  script_xref(name:"IAVA", value:"2023-A-0365-S");
  script_xref(name:"IAVA", value:"2023-A-0559");

  script_name(english:"Oracle Identity Manager (Jul 2023 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"An application on the remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Oracle Identity Manager installed on the remote host is missing a security patch and is,
therefore affected by multiple vulnerabilities as referenced in the July 2023 Critical Patch Update(CPU) advisory.

  - Vulnerability in the Oracle Identity Manager product of Oracle Fusion Middleware (component: Third Party 
    (Spring Framework)). The supported version that is affected is 12.2.1.4.0. Easily exploitable 
    vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Identity 
    Manager. Successful attacks of this vulnerability can result in unauthorized creation, deletion or 
    modification access to critical data or all Oracle Identity Manager accessible data. (CVE-2023-20860)

  - Vulnerability in the Oracle Identity Manager product of Oracle Fusion Middleware (component: Installer 
    (Apache Commons FileUpload)). The supported version that is affected is 12.2.1.4.0. Easily exploitable 
    vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Identity 
    Manager. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or 
    frequently repeatable crash (complete DOS) of Oracle Identity Manager. (CVE-2023-24998)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpuJul2023cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuJul2023.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2023 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20860");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/07/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:identity_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_identity_management_installed.nbin");
  script_require_keys("installed_sw/Oracle Identity Manager");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Oracle Identity Manager');

var constraints = [
  { 'min_version' : '12.2.1.4.0', 'fixed_version' : '12.2.1.4.230708' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
