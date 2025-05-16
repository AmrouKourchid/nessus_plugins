#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(193425);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/18");

  script_cve_id(
    "CVE-2021-23369",
    "CVE-2021-23383",
    "CVE-2022-23491",
    "CVE-2023-2976",
    "CVE-2023-5072",
    "CVE-2023-33201",
    "CVE-2023-33202",
    "CVE-2023-44487",
    "CVE-2023-52428",
    "CVE-2024-21006",
    "CVE-2024-21007",
    "CVE-2024-23635",
    "CVE-2024-25710",
    "CVE-2024-26308"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/10/31");
  script_xref(name:"IAVA", value:"2024-A-0237");
  script_xref(name:"CEA-ID", value:"CEA-2024-0004");

  script_name(english:"Oracle WebLogic Server (April 2024 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The 12.2.1.4.0 and 14.1.1.0.0 versions of WebLogic Server installed on the remote host are affected by multiple
vulnerabilities as referenced in the April 2024 CPU advisory:

  - Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Samples (handlebars)). 
    Supported versions that are affected are 12.2.1.4.0 and 14.1.1.0.0. Easily exploitable vulnerability allows \
    unauthenticated attacker with network access via HTTP to compromise Oracle WebLogic Server. Successful attacks of 
    this vulnerability can result in takeover of Oracle WebLogic Server. (CVE-2021-23369)

  - Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Centralized Thirdparty 
    Jars (Bouncy Castle Java Library)). Supported versions that are affected are 12.2.1.4.0 and 14.1.1.0.0. Easily 
    exploitable vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise 
    Oracle WebLogic Server. Successful attacks of this vulnerability can result in unauthorized read access to a subset 
    of Oracle WebLogic Server accessible data. (CVE-2023-2976)

  - Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Web Container). The 
    supported version that is affected is 14.1.1.0.0. Easily exploitable vulnerability allows unauthenticated attacker 
    with network access via HTTP/2 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can 
    result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of Oracle WebLogic 
    Server. (CVE-2023-44487)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpuapr2024csaf.json");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuapr2024.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2024 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-23383");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/17");

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

include('vcf.inc');
include('vcf_extras_oracle.inc');

var app_info = vcf::oracle_weblogic::get_app_info();

var constraints = [
  { 'min_version' : '12.2.1.4.0', 'fixed_version' : '12.2.1.4.240325', 'fixed_display' : '36440005' },
  { 'min_version' : '14.1.1.0.0', 'fixed_version' : '14.1.1.0.240328', 'fixed_display' : '36454290' }
];

vcf::oracle_weblogic::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE,
    flags:{'xss':TRUE}
);
