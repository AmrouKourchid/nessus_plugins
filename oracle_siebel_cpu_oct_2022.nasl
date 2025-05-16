#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(212450);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/12");

  script_cve_id(
    "CVE-2018-5158",
    "CVE-2020-16856",
    "CVE-2020-36518",
    "CVE-2021-23926",
    "CVE-2021-29425",
    "CVE-2021-30639",
    "CVE-2021-41182",
    "CVE-2022-21598",
    "CVE-2022-22971",
    "CVE-2022-24729",
    "CVE-2022-24785",
    "CVE-2022-25647",
    "CVE-2022-34305"
  );
  script_xref(name:"CEA-ID", value:"CEA-2020-0118");

  script_name(english:"Oracle Siebel Server (October 2022 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The versions of Oracle Siebel CRM installed on the remote host are affected by multiple vulnerabilities as referenced in
the October 2022 CPU advisory.

  - Vulnerability in the Siebel Apps - Marketing product of Oracle Siebel CRM (component: Marketing
    (XMLBeans)). Supported versions that are affected are 22.8 and prior. Easily exploitable vulnerability
    allows unauthenticated attacker with network access via HTTP to compromise Siebel Apps - Marketing.
    Successful attacks of this vulnerability can result in unauthorized access to critical data or complete
    access to all Siebel Apps - Marketing accessible data and unauthorized ability to cause a hang or
    frequently repeatable crash (complete DOS) of Siebel Apps - Marketing. (CVE-2021-23926)

  - Vulnerability in the Siebel Industry - Life Sciences product of Oracle Siebel CRM (component: eDetailing
    (PDF Viewer)). Supported versions that are affected are 22.8 and prior. Easily exploitable vulnerability
    allows unauthenticated attacker with network access via HTTP to compromise Siebel Industry - Life
    Sciences. Successful attacks require human interaction from a person other than the attacker. Successful
    attacks of this vulnerability can result in takeover of Siebel Industry - Life Sciences. (CVE-2018-5158)

  - Vulnerability in the Siebel Engineering - Rel Eng product of Oracle Siebel CRM (component: Build System
    (Visual Studio)). Supported versions that are affected are 22.8 and prior. Easily exploitable
    vulnerability allows unauthenticated attacker with logon to the infrastructure where Siebel Engineering -
    Rel Eng executes to compromise Siebel Engineering - Rel Eng. Successful attacks require human interaction
    from a person other than the attacker. Successful attacks of this vulnerability can result in takeover of
    Siebel Engineering - Rel Eng. (CVE-2020-16856)

  - Vulnerability in the Siebel Core - Automation product of Oracle Siebel CRM (component: Keyword Automation
    (Google Gson)). Supported versions that are affected are 22.8 and prior. Easily exploitable vulnerability
    allows unauthenticated attacker with network access via HTTP to compromise Siebel Core - Automation.
    Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently
    repeatable crash (complete DOS) of Siebel Core - Automation.  Vulnerability in the Siebel Core - Common
    Components product of Oracle Siebel CRM (component: DISA (Google Gson)). Supported versions that are
    affected are 22.8 and prior. Easily exploitable vulnerability allows unauthenticated attacker with network
    access via HTTP to compromise Siebel Core - Common Components. Successful attacks of this vulnerability
    can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of Siebel
    Core - Common Components. (CVE-2022-25647)

  - Vulnerability in the Siebel Core - Common Components product of Oracle Siebel CRM (component: Calendar
    (Moment.js)). Supported versions that are affected are 22.8 and prior. Easily exploitable vulnerability
    allows unauthenticated attacker with network access via HTTP to compromise Siebel Core - Common
    Components. Successful attacks of this vulnerability can result in unauthorized creation, deletion or
    modification access to critical data or all Siebel Core - Common Components accessible data.
    (CVE-2022-24785)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpuoct2022csaf.json");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuoct2022.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2022 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-16856");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-23926");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/18");
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
  { 'fixed_version' : '22.9' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
