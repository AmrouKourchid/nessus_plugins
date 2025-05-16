#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(178485);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/31");

  script_cve_id(
    "CVE-2023-21830",
    "CVE-2023-22006",
    "CVE-2023-22036",
    "CVE-2023-22041",
    "CVE-2023-22043",
    "CVE-2023-22044",
    "CVE-2023-22045",
    "CVE-2023-22049",
    "CVE-2023-22051",
    "CVE-2023-25193",
    "CVE-2022-45688"
  );
  script_xref(name:"IAVA", value:"2023-A-0367-S");

  script_name(english:"Oracle Java SE Multiple Vulnerabilities (July 2023 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle (formerly Sun) Java SE or Java for Business installed on the remote host is affected by multiple
vulnerabilities as referenced in the July 2023 CPU advisory:

  - Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition, Oracle GraalVM for JDK product of 
    Oracle Java SE (component: Utility). Supported versions that are affected are Oracle Java SE: 11.0.19, 
    17.0.7, 20.0.1; Oracle GraalVM Enterprise Edition: 20.3.10, 21.3.6, 22.3.2; Oracle GraalVM for JDK: 
    17.0.7 and 20.0.1. Difficult to exploit vulnerability allows unauthenticated attacker with network 
    access via multiple protocols to compromise Oracle Java SE, Oracle GraalVM Enterprise Edition, Oracle 
    GraalVM for JDK. Successful attacks of this vulnerability can result in unauthorized ability to cause a 
    partial denial of service (partial DOS) of Oracle Java SE, Oracle GraalVM Enterprise Edition, Oracle 
    GraalVM for JDK. (CVE-2023-22036)

  - Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition, Oracle GraalVM for JDK product of
    Oracle Java SE (component: Hotspot). Supported versions that are affected are Oracle Java SE: 8u371-perf, 
    11.0.19, 17.0.7, 20.0.1; Oracle GraalVM Enterprise Edition: 20.3.10, 21.3.6, 22.3.2; Oracle GraalVM for 
    JDK: 17.0.7 and 20.0.1. Difficult to exploit vulnerability allows unauthenticated attacker with logon to 
    the infrastructure where Oracle Java SE, Oracle GraalVM Enterprise Edition, Oracle GraalVM for JDK 
    executes to compromise Oracle Java SE, Oracle GraalVM Enterprise Edition, Oracle GraalVM for JDK. 
    Successful attacks of this vulnerability can result in unauthorized access to critical data or complete 
    access to all Oracle Java SE, Oracle GraalVM Enterprise Edition, Oracle GraalVM for JDK accessible data. 
    (CVE-2023-22041)

  - Vulnerability in Oracle Java SE (component: JavaFX). The supported version that is affected is Oracle 
    Java SE: 8u371. Difficult to exploit vulnerability allows unauthenticated attacker with network access 
    via multiple protocols to compromise Oracle Java SE. Successful attacks of this vulnerability can result 
    in unauthorized creation, deletion or modification access to critical data or all Oracle Java SE 
    accessible data. (CVE-2023-22043)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpujul2023cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujul2023.html#AppendixJAVA");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2023 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Manually scored based on the nature of the vulnerability.");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/07/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jre");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jdk");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("sun_java_jre_installed.nasl", "sun_java_jre_installed_unix.nasl");
  script_require_keys("installed_sw/Java");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_list = ['Oracle Java'];

var app_info = vcf::java::get_app_info(app:app_list);

var constraints = [
  { 'min_version' : '8.0.0', 'fixed_version' : '8.0.381', 'fixed_display' : 'Upgrade to version 8.0.381 or greater' },
  { 'min_version' : '11.0.0', 'fixed_version' : '11.0.20', 'fixed_display' : 'Upgrade to version 11.0.20 or greater' },
  { 'min_version' : '17.0.0', 'fixed_version' : '17.0.8', 'fixed_display' : 'Upgrade to version 17.0.8 or greater' },
  { 'min_version' : '20.0.0', 'fixed_version' : '20.0.2', 'fixed_display' : 'Upgrade to version 20.0.2 or greater' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);

