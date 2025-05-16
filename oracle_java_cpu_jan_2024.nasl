#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(189116);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/19");

  script_cve_id(
    "CVE-2024-20918",
    "CVE-2024-20919",
    "CVE-2024-20921",
    "CVE-2024-20922",
    "CVE-2024-20923",
    "CVE-2024-20925",
    "CVE-2024-20926",
    "CVE-2024-20932",
    "CVE-2024-20945",
    "CVE-2024-20952"
  );
  script_xref(name:"IAVA", value:"2024-A-0033-S");

  script_name(english:"Oracle Java SE Multiple Vulnerabilities (January 2024 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle (formerly Sun) Java SE or Java for Business installed on the remote host is affected by multiple
vulnerabilities as referenced in the January 2024 CPU advisory:

  - Vulnerability in the Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition product of
    Oracle Java SE (component: Hotspot). Supported versions that are affected are Oracle Java SE: 8u391, 
    8u391-perf, 11.0.21, 17.0.9, 21.0.1; Oracle GraalVM for JDK: 17.0.9, 21.0.1; Oracle GraalVM Enterprise 
    Edition: 20.3.12, 21.3.8 and 22.3.4. Difficult to exploit vulnerability allows unauthenticated attacker 
    with network access via multiple protocols to compromise Oracle Java SE, Oracle GraalVM for JDK, Oracle 
    GraalVM Enterprise Edition. Successful attacks of this vulnerability can result in unauthorized creation, 
    deletion or modification access to critical data or all Oracle Java SE, Oracle GraalVM for JDK, Oracle 
    GraalVM Enterprise Edition accessible data as well as unauthorized access to critical data or complete 
    access to all Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition accessible data. 
    (CVE-2024-20918)

  - Vulnerability in the Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition product 
    of Oracle Java SE (component: Hotspot). Supported versions that are affected are Oracle Java SE: 8u391, 
    8u391-perf, 11.0.21, 17.0.9, 21.0.1; Oracle GraalVM for JDK: 17.0.9, 21.0.1; Oracle GraalVM Enterprise 
    Edition: 20.3.12, 21.3.8 and 22.3.4. Difficult to exploit vulnerability allows unauthenticated attacker 
    with network access via multiple protocols to compromise Oracle Java SE, Oracle GraalVM for JDK, Oracle 
    GraalVM Enterprise Edition. Successful attacks of this vulnerability can result in unauthorized access 
    to critical data or complete access to all Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM 
    Enterprise Edition accessible data. (CVE-2024-20921)

  - Vulnerability in the Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition product of 
    Oracle Java SE (component: Security). Supported versions that are affected are Oracle Java SE: 17.0.9; 
    Oracle GraalVM for JDK: 17.0.9; Oracle GraalVM Enterprise Edition: 21.3.8 and 22.3.4. Easily exploitable 
    vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise 
    Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition. Successful attacks of this 
    vulnerability can result in unauthorized creation, deletion or modification access to critical data or 
    all Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition accessible data. 
    (CVE-2024-20932)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpujan2024cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujan2024.html#AppendixJAVA");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2024 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20932");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jre");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jdk");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("sun_java_jre_installed.nasl", "sun_java_jre_installed_unix.nasl");
  script_require_keys("installed_sw/Java");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_list = ['Oracle Java'];

var app_info = vcf::java::get_app_info(app:app_list);

var constraints = [
  { 'min_version' : '8.0.0', 'fixed_version' : '8.0.401', 'fixed_display' : 'Upgrade to version 8.0.401 or greater' },
  { 'min_version' : '11.0.0', 'fixed_version' : '11.0.22', 'fixed_display' : 'Upgrade to version 11.0.22 or greater' },
  { 'min_version' : '17.0.0', 'fixed_version' : '17.0.10', 'fixed_display' : 'Upgrade to version 17.0.10 or greater' },
  { 'min_version' : '21.0.0', 'fixed_version' : '21.0.2', 'fixed_display' : 'Upgrade to version 21.0.2 or greater' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);

