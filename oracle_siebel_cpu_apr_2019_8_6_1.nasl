#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(212392);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/12");

  script_cve_id(
    "CVE-2014-0107",
    "CVE-2014-0114",
    "CVE-2015-1832",
    "CVE-2016-2141",
    "CVE-2016-1000031",
    "CVE-2019-2719"
  );
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"Oracle Siebel Server 8.5.1.x <= 8.5.1.7 / 8.6.0 / 8.6.1 (April 2019 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The versions of Oracle Siebel CRM installed on the remote host are affected by multiple vulnerabilities as referenced in
the April 2019 CPU advisory.

  - Vulnerability in the Oracle Knowledge component of Oracle Siebel CRM (subcomponent: Information Manager 
    Console (Apache Xalan)). Supported versions that are affected are 8.5.1.0 - 8.5.1.7, 8.6.0 and 8.6.1.
    Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to 
    compromise Oracle Knowledge. Successful attacks of this vulnerability can result in unauthorized update,
    insert or delete access to some of Oracle Knowledge accessible data as well as unauthorized read access
    to a subset of Oracle Knowledge accessible data and unauthorized ability to cause a partial denial of 
    service (partial DOS) of Oracle Knowledge. (CVE-2014-0107)
    
  - Vulnerability in the Oracle Knowledge component of Oracle Siebel CRM (subcomponent: Information Manager
    Console (Apache Commons BeanUtils)). Supported versions that are affected are 8.5.1.0 - 8.5.1.7, 8.6.0 and
    8.6.1. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to
    compromise Oracle Knowledge. Successful attacks of this vulnerability can result in takeover of Oracle
    Knowledge. (CVE-2014-0114)

  - Vulnerability in the Oracle Knowledge component of Oracle Siebel CRM (subcomponent: Information Manager
    Console (Apache Derby)). Supported versions that are affected are 8.5.1.0 - 8.5.1.7, 8.6.0 and 8.6.1.
    Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to
    compromise Oracle Knowledge. Successful attacks of this vulnerability can result in unauthorized access to
    critical data or complete access to all Oracle Knowledge accessible data and unauthorized ability to cause
    a hang or frequently repeatable crash (complete DOS) of Oracle Knowledge. (CVE-2015-1832)
    
  - Vulnerability in the Oracle Knowledge component of Oracle Siebel CRM (subcomponent: Information Manager
    Console (JGroups)). Supported versions that are affected are 8.5.1.0 - 8.5.1.7, 8.6.0 and 8.6.1. Easily
    exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise
    Oracle Knowledge. Successful attacks of this vulnerability can result in takeover of Oracle Knowledge.
    (CVE-2016-2141)

  - Vulnerability in the Oracle Knowledge component of Oracle Siebel CRM (subcomponent: Information Manager
    Console (Apache Commons FileUpload)). Supported versions that are affected are 8.5.1.0 - 8.5.1.7, 8.6.0
    and 8.6.1. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP
    to compromise Oracle Knowledge. Successful attacks of this vulnerability can result in takeover of Oracle
    Knowledge. (CVE-2016-1000031)

  - Vulnerability in the Oracle Knowledge component of Oracle Siebel CRM (subcomponent: Web Applications 
    (InfoCenter)). Supported versions that are affected are 8.5.1.0 - 8.5.1.7, 8.6.0 and 8.6.1. Easily
    exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise
    Oracle Knowledge. Successful attacks require human interaction from a person other than the attacker and 
    while the vulnerability is in Oracle Knowledge, attacks may significantly impact additional products.
    Successful attacks of this vulnerability can result in unauthorized update, insert or delete access to
    some of Oracle Knowledge accessible data as well as unauthorized read access to a subset of Oracle
    Knowledge accessible data. (CVE-2019-2719)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # http://www.oracle.com/technetwork/security-advisory/cpuapr2019-5072813.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f9f982b9");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2019 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-2141");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apache Struts ClassLoader Manipulation Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/16");
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
  { 'min_version' : '8.5.1.0', 'max_version' : '8.5.1.7', 'fixed_display' : 'See vendor advisory' },
  { 'min_version' : '8.6.0', 'max_version' : '8.6.1', 'fixed_display' : 'See vendor advisory' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
