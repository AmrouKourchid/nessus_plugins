#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(202719);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/18");

  script_cve_id("CVE-2023-37536", "CVE-2024-26308");
  script_xref(name:"IAVA", value:"2024-A-0426-S");

  script_name(english:"Oracle Essbase Multiple Vulnerabilities (July 2024 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"A business analytics solution installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle Essbase installed on the remote host is missing a security patch from the July 2024
Critical Patch Update (CPU). It is, therefore, affected by:

  - Vulnerability in Oracle Essbase (component: Essbase Web Platform (Apache Xerces-C++)). The supported version that 
    is affected is 21.5.6. Easily exploitable vulnerability allows high privileged attacker with logon to the 
    infrastructure where Oracle Essbase executes to compromise Oracle Essbase. Successful attacks of this 
    vulnerability can result in takeover of Oracle Essbase. (CVE-2023-37536)

  - Vulnerability in Oracle Essbase (component: Essbase Web Platform (Apache Commons Compress)). The supported version 
    that is affected is 21.5.6. Easily exploitable vulnerability allows unauthenticated attacker with logon to the 
    infrastructure where Oracle Essbase executes to compromise Oracle Essbase. Successful attacks require human 
    interaction from a person other than the attacker. Successful attacks of this vulnerability can result in 
    unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of Oracle Essbase.
    (CVE-2024-26308)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpujul2024csaf.json");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujul2024.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2024 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-37536");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/06/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/19");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:essbase");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_essbase_installed.nbin");
  script_require_keys("Settings/ParanoidReport", "installed_sw/Oracle Essbase");

  exit(0);
}

include('vcf.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

var app_info = vcf::get_app_info(app:'Oracle Essbase');

var constraints = [
  { 'equal' : '21.5.6.0.0', 'fixed_display' : '21.5.6.0.0 Patch 36282078 or later'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
