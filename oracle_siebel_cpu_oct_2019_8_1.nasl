#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(212393);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/12");

  script_cve_id("CVE-2019-11358");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"Oracle Siebel Server 8.1.1.9 <= 19.8 (October 2019 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a vulnerability");
  script_set_attribute(attribute:"description", value:
"The versions of Oracle Siebel CRM installed on the remote host are affected by a vulnerability as referenced in
the October 2019 CPU advisory.

  - Vulnerability in the Siebel Mobile Applications product of Oracle Siebel CRM (component: CG Mobile 
  Connected (jQuery)). Supported versions that are affected are 19.8 and prior. Easily exploitable 
  vulnerability allows unauthenticated attacker with network access via HTTP to compromise Siebel
  Mobile Applications. Successful attacks require human interaction from a person other than the attacker and 
  while the vulnerability is in Siebel Mobile Applications, attacks may significantly impact additional
  products. Successful attacks of this vulnerability can result in unauthorized update, insert or delete
  access to some of Siebel Mobile Applications accessible data as well as unauthorized read access to a subset
  of Siebel Mobile Applications accessible data. (CVE-2019-11358)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuoct2019.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2019 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11358");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:siebel_crm");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_siebel_server_installed.nbin");
  script_require_keys("installed_sw/Oracle Siebel Server");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Oracle Siebel Server');

var constraints = [
  { 'min_version' : '8.1.1.9', 'max_version' : '19.8', 'fixed_display' : 'See vendor advisory' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
