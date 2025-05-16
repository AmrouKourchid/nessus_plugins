#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(189176);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/22");

  script_cve_id(
    "CVE-2022-46337",
    "CVE-2023-42503",
    "CVE-2023-43643",
    "CVE-2023-44483",
    "CVE-2023-49093",
    "CVE-2024-20927",
    "CVE-2024-20931",
    "CVE-2024-20986"
  );
  script_xref(name:"IAVA", value:"2024-A-0031");

  script_name(english:"Oracle WebLogic Server (January 2024 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"An application server installed on the remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Oracle WebLogic Server installed on the remote host is missing a security patch from the January 2024
Critical Patch Update (CPU). It is, therefore, affected by multiple vulnerabilities, including:

  - Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Centralized Thirdparty
    Jars (NekoHTML)). Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to
    compromise Oracle WebLogic Server. Successful attacks require human interaction from a person other than the 
    attacker. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server.
    (CVE-2023-49093)

  - Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Core). Easily 
    exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle 
    WebLogic Server. While the vulnerability is in Oracle WebLogic Server, attacks may significantly impact additional 
    products (scope change). Successful attacks of this vulnerability can result in unauthorized creation, deletion or 
    modification access to critical data or all Oracle WebLogic Server accessible data. (CVE-2024-20927)

  - Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Core). Easily 
    exploitable vulnerability allows unauthenticated attacker with network access via T3, IIOP to compromise Oracle 
    WebLogic Server. Successful attacks of this vulnerability can result in unauthorized access to critical data or 
    complete access to all Oracle WebLogic Server accessible data. (CVE-2024-20931)

  Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpujan2024csaf.json");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujan2024.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2024 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-49093");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-46337");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:weblogic_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_weblogic_server_installed.nbin", "os_fingerprint.nasl");
  script_require_ports("installed_sw/Oracle WebLogic Server", "installed_sw/Oracle Data Integrator Embedded Weblogic Server");

  exit(0);
}

include('vcf_extras_oracle.inc');

var app_info = vcf::oracle_weblogic::get_app_info();

var constraints = [
  { 'min_version' : '12.2.1.4.0', 'fixed_version' : '12.2.1.4.240104', 'fixed_display' : '36155700 or 36178496' },
  { 'min_version' : '14.1.1.0.0', 'fixed_version' : '14.1.1.0.231220', 'fixed_display' : '36124787 or 36178511' }
];

vcf::oracle_weblogic::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
