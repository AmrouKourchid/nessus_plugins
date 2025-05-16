#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(212407);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/12");

  script_cve_id("CVE-2019-16943", "CVE-2020-1938", "CVE-2020-9488");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/17");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2020-0021");

  script_name(english:"Oracle Siebel Server (July 2020 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The versions of Oracle Siebel CRM installed on the remote host are affected by multiple vulnerabilities as referenced in
the July 2020 CPU advisory.

  - Vulnerability in the Siebel UI Framework product of Oracle Siebel CRM (component: EAI, SWSE (Apache
    Tomcat)). Supported versions that are affected are 20.5 and prior. Easily exploitable vulnerability allows
    unauthenticated attacker with network access via multiple protocols to compromise Siebel UI Framework.
    Successful attacks of this vulnerability can result in takeover of Siebel UI Framework. (CVE-2020-1938)

  - Vulnerability in the Siebel UI Framework product of Oracle Siebel CRM (component: EAI (jackson-databind)).
    Supported versions that are affected are 20.5 and prior. Easily exploitable vulnerability allows
    unauthenticated attacker with network access via HTTP to compromise Siebel UI Framework. Successful
    attacks of this vulnerability can result in takeover of Siebel UI Framework. (CVE-2019-16943)

  - Vulnerability in the Siebel Engineering - Installer and Deployment product of Oracle Siebel CRM 
    (component: Siebel Approval Manager (jackson-databind)). Supported versions that are affected are 2.20.5
    and prior. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP
    to compromise Siebel Engineering - Installer and Deployment. Successful attacks of this vulnerability can 
    result in takeover of Siebel Engineering - Installer and Deployment. (CVE-2019-16943)

  - Vulnerability in the Siebel Engineering - Installer and Deployment product of Oracle Siebel CRM
    (component: Siebel Approval Manager (Log4j)). Supported versions that are affected are 2.20.5 and prior.
    Difficult to exploit vulnerability allows unauthenticated attacker with network access via SMTPS to
    compromise Siebel Engineering - Installer and Deployment. Successful attacks of this vulnerability can
    result in unauthorized read access to a subset of Siebel Engineering - Installer and Deployment accessible
    data. (CVE-2020-9488)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpujul2020cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujul2020.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2020 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1938");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/14");
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
  { 'fixed_version' : '20.6' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
