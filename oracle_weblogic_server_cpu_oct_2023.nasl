#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(183311);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/04");

  script_cve_id(
    "CVE-2020-13956",
    "CVE-2021-36374",
    "CVE-2022-23491",
    "CVE-2022-29546",
    "CVE-2022-29599",
    "CVE-2022-42920",
    "CVE-2022-44729",
    "CVE-2023-2976",
    "CVE-2023-22069",
    "CVE-2023-22072",
    "CVE-2023-22086",
    "CVE-2023-22089",
    "CVE-2023-22101",
    "CVE-2023-22108",
    "CVE-2023-35116"
  );
  script_xref(name:"IAVA", value:"2023-A-0556");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Oracle WebLogic Server (October 2023 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"An application server installed on the remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Oracle WebLogic Server installed on the remote host is missing a security patch from the October 2023
Critical Patch Update (CPU). It is, therefore, affected by multiple vulnerabilities, including:

  - Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Core (Apache
    Commons BCEL)). Supported versions that are affected are 12.2.1.4.0 and 14.1.1.0.0. Easily exploitable
    vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle WebLogic
    Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server
    (CVE-2022-42920)

  - Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Centralized
    Thirdparty Jars (Apache Maven Shared Utils)). The supported version that is affected is 14.1.1.0.0. Easily
    exploitable vulnerability allows unauthenticated attacker with network access via multiple protocols to
    compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of
    Oracle WebLogic Server. (CVE-2022-29599)

  - Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Core).
    Supported versions that are affected are 12.2.1.4.0 and 14.1.1.0.0. Easily exploitable vulnerability
    allows unauthenticated attacker with network access via T3, IIOP to compromise Oracle WebLogic Server.
    Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server.
    (CVE-2023-22069)

  Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpuoct2023cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuoct2023.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2023 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-29599");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-22089");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:weblogic_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_weblogic_server_installed.nbin", "os_fingerprint.nasl");
  script_require_ports("installed_sw/Oracle WebLogic Server", "installed_sw/Oracle Data Integrator Embedded Weblogic Server");

  exit(0);
}

include('vcf_extras_oracle.inc');

var app_info = vcf::oracle_weblogic::get_app_info();

var constraints = [
  # 12.2.1.3 patch is a PSU overlay patch with same fixed_version 12.2.1.3.230402 as April patch. I'm incrementing it
  # here to flag them for missing this overlay patch
  { 'min_version' : '12.2.1.3.0', 'fixed_version' : '12.2.1.3.230403', 'fixed_display' : '35787725' },
  { 'min_version' : '12.2.1.4.0', 'fixed_version' : '12.2.1.4.231010', 'fixed_display' : '35893811 or 35899167' },
  { 'min_version' : '14.1.1.0.0', 'fixed_version' : '14.1.1.0.231012', 'fixed_display' : '35904051 or 35908319' }
];

vcf::oracle_weblogic::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
