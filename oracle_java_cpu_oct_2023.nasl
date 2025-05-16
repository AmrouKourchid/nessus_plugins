#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(183295);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/10/24");

  script_cve_id("CVE-2023-22067", "CVE-2023-22081", "CVE-2023-22025");
  script_xref(name:"IAVA", value:"2023-A-0561");

  script_name(english:"Oracle Java SE Multiple Vulnerabilities (October 2023 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle (formerly Sun) Java SE or Java for Business installed on the remote host is affected by multiple
vulnerabilities as referenced in the October 2023 CPU advisory:

  - Vulnerability in Oracle Java SE (component: CORBA). Supported versions that are affected are Oracle Java 
    SE: 8u381 and 8u381-perf. Easily exploitable vulnerability allows unauthenticated attacker with network 
    access via CORBA to compromise Oracle Java SE. Successful attacks of this vulnerability can result in 
    unauthorized update, insert or delete access to some of Oracle Java SE accessible data. (CVE-2023-22067)

  - Vulnerability in the Oracle Java SE, Oracle GraalVM for JDK product of Oracle Java SE (component: JSSE). 
    Supported versions that are affected are Oracle Java SE: 8u381, 8u381-perf, 11.0.20, 17.0.8, 20.0.2; 
    Oracle GraalVM for JDK: 17.0.8 and 20.0.2. Easily exploitable vulnerability allows unauthenticated 
    attacker with network access via HTTPS to compromise Oracle Java SE, Oracle GraalVM for JDK. Successful 
    attacks of this vulnerability can result in unauthorized ability to cause a partial denial of service 
    (partial DOS) of Oracle Java SE, Oracle GraalVM for JDK. (CVE-2023-22081)

  - CVE-2023-22025	Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition, Oracle GraalVM 
    for JDK product of Oracle Java SE (component: Hotspot). Supported versions that are affected are Oracle 
    Java SE: 8u381-perf, 17.0.8, 20.0.2; Oracle GraalVM for JDK: 17.0.8 and 20.0.2. Difficult to exploit 
    vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise 
    Oracle Java SE, Oracle GraalVM Enterprise Edition, Oracle GraalVM for JDK. Successful attacks of this 
    vulnerability can result in unauthorized update, insert or delete access to some of Oracle Java SE, 
    Oracle GraalVM Enterprise Edition, Oracle GraalVM for JDK accessible data. (CVE-2023-22025)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpuoct2023cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuoct2023.html#AppendixJAVA");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2023 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-22067");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jre");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jdk");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("sun_java_jre_installed.nasl", "sun_java_jre_installed_unix.nasl");
  script_require_keys("installed_sw/Java");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_list = ['Oracle Java'];

var app_info = vcf::java::get_app_info(app:app_list);

var constraints = [
  { 'min_version' : '8.0.0', 'fixed_version' : '8.0.391', 'fixed_display' : 'Upgrade to version 8.0.391 or greater' },
  { 'min_version' : '11.0.0', 'fixed_version' : '11.0.21', 'fixed_display' : 'Upgrade to version 11.0.21 or greater' },
  { 'min_version' : '17.0.0', 'fixed_version' : '17.0.9', 'fixed_display' : 'Upgrade to version 17.0.9 or greater' },
  { 'min_version' : '21.0.0', 'fixed_version' : '21.0.1', 'fixed_display' : 'Upgrade to version 21.0.1 or greater' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

