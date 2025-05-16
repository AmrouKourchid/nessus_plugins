#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(209282);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/24");

  script_cve_id(
    "CVE-2024-36138",
    "CVE-2024-21208",
    "CVE-2024-21210",
    "CVE-2024-21211",
    "CVE-2024-21217",
    "CVE-2024-21235",
    "CVE-2024-22020",
    "CVE-2024-25062"
  );
  script_xref(name:"IAVA", value:"2024-A-0657-S");

  script_name(english:"Oracle Java SE Multiple Vulnerabilities (October 2024 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The versions of Java installed on the remote host are affected by multiple vulnerabilities as referenced in the
October 2024 CPU advisory.

  - Vulnerability in the Oracle GraalVM for JDK product of Oracle Java SE (component: Node (Node.js)). Supported
    versions that are affected are Oracle GraalVM for JDK: 17.0.12, 21.0.4 and 23. Difficult to exploit
    vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise Oracle GraalVM
    for JDK. Successful attacks of this vulnerability can result in takeover of Oracle GraalVM for JDK. (CVE-2024-36138)

  - Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component:
    JavaFX (WebKitGTK)). Supported versions that are affected are Oracle Java SE: 8u421; Oracle GraalVM
    Enterprise Edition: 20.3.15 and 21.3.11. Difficult to exploit vulnerability allows unauthenticated attacker with
    network access via multiple protocols to compromise Oracle Java SE, Oracle GraalVM Enterprise Edition. Successful
    attacks require human interaction from a person other than the attacker. Successful attacks of this
    vulnerability can result in takeover of Oracle Java SE, Oracle GraalVM Enterprise Edition. (CVE-2023-42950)

  - Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component:
    JavaFX (libxml2)). Supported versions that are affected are Oracle Java SE: 8u421; Oracle GraalVM Enterprise
    Edition: 20.3.15 and 21.3.11. Easily exploitable vulnerability allows unauthenticated attacker with network
    access via multiple protocols to compromise Oracle Java SE, Oracle GraalVM Enterprise Edition. Successful
    attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash
    (complete DOS) of Oracle Java SE, Oracle GraalVM Enterprise Edition. (CVE-2024-25062)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpuoct2024csaf.json");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuoct2024.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2024 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-36138");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-21235");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jre");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jdk");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("sun_java_jre_installed.nasl", "sun_java_jre_installed_unix.nasl");
  script_require_keys("installed_sw/Java");

  exit(0);
}

include('vcf_extras.inc');

var app_list = ['Oracle Java'];

var app_info = vcf::java::get_app_info(app:app_list);

var constraints = [
  { 'min_version' : '8.0.0', 'fixed_version' : '8.0.431', 'fixed_display' : 'Upgrade to version 8.0.431 or greater' },
  { 'min_version' : '11.0.0', 'fixed_version' : '11.0.25', 'fixed_display' : 'Upgrade to version 11.0.25 or greater' },
  { 'min_version' : '17.0.0', 'fixed_version' : '17.0.13', 'fixed_display' : 'Upgrade to version 17.0.13 or greater' },
  { 'min_version' : '20.0.0', 'fixed_version' : '20.3.16', 'fixed_display' : 'Upgrade to version 20.3.16 or greater' },
  { 'min_version' : '21.0.0', 'fixed_version' : '21.0.5', 'fixed_display' : 'Upgrade to version 21.0.5 or greater' },
  { 'min_version' : '23.0.0', 'fixed_version' : '23.0.1', 'fixed_display' : 'Upgrade to version 23.0.1 or greater' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
