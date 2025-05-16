#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(193574);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/14");

  script_cve_id(
    "CVE-2023-32643",
    "CVE-2023-41993",
    "CVE-2024-20954",
    "CVE-2024-21002",
    "CVE-2024-21003",
    "CVE-2024-21004",
    "CVE-2024-21005",
    "CVE-2024-21011",
    "CVE-2024-21012",
    "CVE-2024-21068",
    "CVE-2024-21085",
    "CVE-2024-21094",
    "CVE-2024-21098",
    "CVE-2024-21892"
  );
  script_xref(name:"IAVA", value:"2024-A-0239");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/10/16");
  script_xref(name:"IAVA", value:"2024-A-0239");

  script_name(english:"Oracle Java (Apr 2024 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The 8u401, 20.3.13, 21.3.9, 11.0.23, 17.0.10, 21.0.3, 22, and perf versions of Java installed on the remote host are
affected by multiple vulnerabilities as referenced in the April 2024 CPU advisory.

  - Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE 
    (component: JavaFX (WebKitGTK)). Supported versions that are affected are Oracle Java SE: 8u401; Oracle 
    GraalVM Enterprise Edition: 20.3.13 and 21.3.9. Difficult to exploit vulnerability allows unauthenticated
    attacker with network access via multiple protocols to compromise Oracle Java SE, Oracle GraalVM Enterprise 
    Edition. Successful attacks require human interaction from a person other than the attacker. Successful 
    attacks of this vulnerability can result in takeover of Oracle Java SE, Oracle GraalVM Enterprise 
    Edition.(CVE-2023-41993)

  - Vulnerability in the Oracle GraalVM for JDK product of Oracle Java SE (component: Node (Node.js)). Supported 
    versions that are affected are Oracle GraalVM for JDK: 17.0.10, 21.0.2 and 22. Difficult to exploit vulnerability 
    allows low privileged attacker with logon to the infrastructure where Oracle GraalVM for JDK executes to 
    compromise Oracle GraalVM for JDK. While the vulnerability is in Oracle GraalVM for JDK, attacks may significantly 
    impact additional products (scope change). Successful attacks of this vulnerability can result in unauthorized 
    creation, deletion or modification access to critical data or all Oracle GraalVM for JDK accessible data as well 
    as unauthorized access to critical data or complete access to all Oracle GraalVM for JDK accessible data.
    (CVE-2024-21892)

  - Vulnerability in the Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition product of 
    Oracle Java SE (component: Hotspot). Supported versions that are affected are Oracle Java SE: 8u401, 8u401-perf, 
    11.0.23, 17.0.10, 21.0.3, 22; Oracle GraalVM for JDK: 17.0.10, 21.0.3, 22; Oracle GraalVM Enterprise Edition: 
    20.3.13 and 21.3.9. Difficult to exploit vulnerability allows unauthenticated attacker with network access 
    via multiple protocols to compromise Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition. 
    Successful attacks of this vulnerability can result in unauthorized ability to cause a partial denial of 
    service (partial DOS) of Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition. 
    (CVE-2024-21011)


Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpuapr2024csaf.json");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuapr2024.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2024 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-41993");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jre");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jdk");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("sun_java_jre_installed.nasl", "sun_java_jre_installed_unix.nasl");
  script_require_keys("installed_sw/Java");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_list = ['Oracle Java'];

var app_info = vcf::java::get_app_info(app:app_list);

var constraints = [
  { 'min_version' : '8.0.0', 'fixed_version' : '8.0.411', 'fixed_display' : 'Upgrade to version 8.0.411 or greater' },
  { 'min_version' : '11.0.0', 'fixed_version' : '11.0.23', 'fixed_display' : 'Upgrade to version 11.0.23 or greater' },
  { 'min_version' : '17.0.0', 'fixed_version' : '17.0.11', 'fixed_display' : 'Upgrade to version 17.0.11 or greater' },
  { 'min_version' : '21.0.0', 'fixed_version' : '21.0.3', 'fixed_display' : 'Upgrade to version 21.0.3 or greater' },
  { 'min_version' : '22.0.0', 'fixed_version' : '22.0.1', 'fixed_display' : 'Upgrade to version 22.0.1 or greater' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
