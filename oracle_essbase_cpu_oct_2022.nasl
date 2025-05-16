#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(181757);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/09/25");

  script_cve_id("CVE-2021-22946", "CVE-2021-44832");
  script_xref(name:"IAVA", value:"2022-A-0436-S");

  script_name(english:"Oracle Essbase Multiple Vulnerabilities (October 2022 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"A business analytics solution installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle Essbase installed on the remote host is missing a security patch from the October 2022
Critical Patch Update (CPU). It is, therefore, affected by multiple vulnerabilities, including:

  - Vulnerability in Oracle Essbase (component: Build (cURL)). The supported version that is affected is 21.3. 
    Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTPS to compromise 
    Oracle Essbase. Successful attacks of this vulnerability can result in unauthorized access to critical data 
    or complete access to all Oracle Essbase accessible data. (CVE-2021-22946)

  - Vulnerability in Oracle Essbase (component: Essbase Web Platform (Apache Log4j)). The supported version that is 
    affected is 21.3. Difficult to exploit vulnerability allows high privileged attacker with network access via HTTP 
    to compromise Oracle Essbase. Successful attacks of this vulnerability can result in takeover of Oracle Essbase.
    (CVE-2021-44832)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpuoct2022cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuoct2022.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2022 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-44832");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-22946");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:essbase");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_essbase_installed.nbin");
  script_require_keys("installed_sw/Oracle Essbase");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Oracle Essbase');

var constraints = [
  { 'min_version' : '21.3.0.0', 'fixed_version' : '21.4.0.0.0', 'fixed_display' : '21.4.0.0 (Patch 33460488)'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);