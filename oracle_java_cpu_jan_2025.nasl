#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(214532);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/17");

  script_cve_id("CVE-2025-0509", "CVE-2025-21502");
  script_xref(name:"IAVA", value:"2025-A-0049-S");

  script_name(english:"Oracle Java SE Multiple Vulnerabilities (January 2025 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The 8u431, 11.0.26, 17.0.14, 20.3.16, 21.0.5, 21.3.12, 23.0.2, and perf versions of Java installed on the remote host
are affected by multiple vulnerabilities as referenced in the January 2025 CPU advisory.

  - Vulnerability in Oracle Java SE (component: Install (Sparkle)). The supported version that is affected is
    Oracle Java SE: 8u431. Difficult to exploit vulnerability allows high privileged attacker with access to
    the physical communication segment attached to the hardware where the Oracle Java SE executes to
    compromise Oracle Java SE. Successful attacks require human interaction from a person other than the
    attacker and while the vulnerability is in Oracle Java SE, attacks may significantly impact additional
    products (scope change). Successful attacks of this vulnerability can result in takeover of Oracle Java
    SE. Note: Only applies to the macOS autoupdater. (CVE-2025-0509)

  - Vulnerability in the Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition product of
    Oracle Java SE (component: Hotspot). Supported versions that are affected are Oracle Java SE: 8u431-perf,
    11.0.26, 17.0.14, 21.0.5, 23.0.2; Oracle GraalVM for JDK: 17.0.14, 21.0.5, 23.0.2; Oracle GraalVM
    Enterprise Edition: 20.3.16 and 21.3.12. Difficult to exploit vulnerability allows unauthenticated
    attacker with network access via multiple protocols to compromise Oracle Java SE, Oracle GraalVM for JDK,
    Oracle GraalVM Enterprise Edition. Successful attacks of this vulnerability can result in unauthorized
    update, insert or delete access to some of Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM
    Enterprise Edition accessible data as well as unauthorized read access to a subset of Oracle Java SE,
    Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition accessible data. Note: This vulnerability can be
    exploited by using APIs in the specified Component, e.g., through a web service which supplies data to the
    APIs. This vulnerability also applies to Java deployments, typically in clients running sandboxed Java Web
    Start applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes from
    the internet) and rely on the Java sandbox for security. (CVE-2025-21502)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpujan2025csaf.json");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujan2025.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2025 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:H/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:H/PR:H/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-0509");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/01/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/01/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jre");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jdk");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
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

#TODO: Update constraints accordingly based on Oracle CPU data
var constraints = [
  { 'min_version' : '8.0.0', 'fixed_version' : '8.0.441', 'fixed_display' : 'Upgrade to version 8.0.441 or greater' },
  { 'min_version' : '11.0.0', 'fixed_version' : '11.0.26', 'fixed_display' : 'Upgrade to version 11.0.26 or greater' },
  { 'min_version' : '17.0.0', 'fixed_version' : '17.0.14', 'fixed_display' : 'Upgrade to version 17.0.14 or greater' },
  { 'min_version' : '20.0.0', 'fixed_version' : '20.3.16', 'fixed_display' : 'Upgrade to version 20.3.16 or greater' },
  { 'min_version' : '21.0.0', 'fixed_version' : '21.0.6', 'fixed_display' : 'Upgrade to version 21.0.6 or greater' },
  { 'min_version' : '23.0.0', 'fixed_version' : '23.0.2', 'fixed_display' : 'Upgrade to version 23.0.2 or greater' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
