#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(234624);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/18");

  script_cve_id(
    "CVE-2024-27856",
    "CVE-2024-40866",
    "CVE-2024-44185",
    "CVE-2024-44187",
    "CVE-2024-44244",
    "CVE-2024-44296",
    "CVE-2024-44308",
    "CVE-2024-44309",
    "CVE-2024-47544",
    "CVE-2024-47545",
    "CVE-2024-47546",
    "CVE-2024-47596",
    "CVE-2024-47597",
    "CVE-2024-47606",
    "CVE-2024-47775",
    "CVE-2024-47776",
    "CVE-2024-47777",
    "CVE-2024-47778",
    "CVE-2024-54479",
    "CVE-2024-54502",
    "CVE-2024-54505",
    "CVE-2024-54508",
    "CVE-2024-54534",
    "CVE-2024-54543",
    "CVE-2025-23083",
    "CVE-2025-23084",
    "CVE-2025-23085",
    "CVE-2025-21587",
    "CVE-2025-24143",
    "CVE-2025-24150",
    "CVE-2025-24158",
    "CVE-2025-24162",
    "CVE-2025-30691",
    "CVE-2025-30698"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/12/12");

  script_name(english:"Oracle Java SE Multiple Vulnerabilities (April 2025 CPU)");
  script_xref(name:"IAVA", value:"2025-A-0271");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The versions of Java installed on the remote host are affected by multiple vulnerabilities as referenced in the April 
2025 CPU advisory.

  - Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE 
    (component: JavaFX (gstreamer)). Supported versions that are affected are Oracle Java SE: 8u441, 
    8u441-perf; Oracle GraalVM Enterprise Edition: 20.3.17 and 21.3.13. Difficult to exploit vulnerability 
    allows unauthenticated attacker with network access via multiple protocols to compromise Oracle Java SE, 
    Oracle GraalVM Enterprise Edition. Successful attacks require human interaction from a person other than 
    the attacker. Successful attacks of this vulnerability can result in takeover of Oracle Java SE, Oracle 
    GraalVM Enterprise Edition. (CVE-2024-47606)

  - Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE 
    (component: JavaFX (WebKitGTK)). Supported versions that are affected are Oracle Java SE: 8u441; Oracle 
    GraalVM Enterprise Edition: 20.3.17 and 21.3.13. Difficult to exploit vulnerability allows 
    unauthenticated attacker with network access via multiple protocols to compromise Oracle Java SE, Oracle 
    GraalVM Enterprise Edition. Successful attacks require human interaction from a person other than the 
    attacker. Successful attacks of this vulnerability can result in takeover of Oracle Java SE, Oracle 
    GraalVM Enterprise Edition. (CVE-2024-54534)

  - Vulnerability in the Oracle GraalVM for JDK product of Oracle Java SE (component: Node (Node.js)). 
    Supported versions that are affected are Oracle GraalVM for JDK: 17.0.14 and 21.0.6. Easily exploitable 
    vulnerability allows unauthenticated attacker with logon to the infrastructure where Oracle GraalVM for 
    JDK executes to compromise Oracle GraalVM for JDK. Successful attacks of this vulnerability can result in
     unauthorized creation, deletion or modification access to critical data or all Oracle GraalVM for JDK 
     accessible data as well as unauthorized access to critical data or complete access to all Oracle GraalVM 
     for JDK accessible data. (CVE-2025-23083)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpuapr2025csaf.json");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuapr2025.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2025 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-47606");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-47606");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/04/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jre");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jdk");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("sun_java_jre_installed.nasl", "sun_java_jre_installed_unix.nasl");
  script_require_keys("installed_sw/Java");

  exit(0);
}

include('vcf_extras.inc');

var app_list = ['Oracle Java'];

var app_info = vcf::java::get_app_info(app:app_list);

var constraints = [
  { 'min_version' : '8.0.0', 'fixed_version' : '8.0.451', 'fixed_display' : 'Upgrade to version 8.0.451 or greater' },
  { 'min_version' : '11.0.0', 'fixed_version' : '11.0.27', 'fixed_display' : 'Upgrade to version 11.0.27 or greater' },
  { 'min_version' : '17.0.0', 'fixed_version' : '17.0.15', 'fixed_display' : 'Upgrade to version 17.0.15 or greater' },
  { 'min_version' : '21.0.0', 'fixed_version' : '21.0.7', 'fixed_display' : 'Upgrade to version 21.0.7 or greater' },
  { 'min_version' : '24.0.0', 'fixed_version' : '24.0.1', 'fixed_display' : 'Upgrade to version 24.0.1 or greater' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
