#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152021);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/06");

  script_cve_id(
    "CVE-2021-2341",
    "CVE-2021-2369",
    "CVE-2021-2388",
    "CVE-2021-2432"
  );
  script_xref(name:"IAVA", value:"2021-A-0327-S");

  script_name(english:"Oracle Java SE 1.7.0_311 / 1.8.0_301 / 1.11.0_12 / 1.16.0_2 Multiple Vulnerabilities (Unix July 2021 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle (formerly Sun) Java SE or Java for Business installed on the remote host is prior to 7 Update
301, 8 Update 291, 11 Update 11, or 16 Update 1. It is, therefore, affected by multiple vulnerabilities as referenced
in the July 2021 CPU advisory:

  - Vulnerability in the Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component: Networking). 
    Supported versions that are affected are Java SE: 7u301, 8u291, 11.0.11, 16.0.1; Oracle GraalVM Enterprise Edition: 
    20.3.2 and 21.1.0. Difficult to exploit vulnerability allows unauthenticated attacker with network access via 
    multiple protocols to compromise Java SE, Oracle GraalVM Enterprise Edition. Successful attacks require human 
    interaction from a person other than the attacker. Successful attacks of this vulnerability can result in 
    unauthorized read access to a subset of Java SE, Oracle GraalVM Enterprise Edition accessible data. This 
    vulnerability applies to Java deployments, typically in clients running sandboxed Java Web Start applications or 
    sandboxed Java applets, that load and run untrusted code (e.g., code that comes from the internet) and rely on the 
    Java sandbox for security. This vulnerability does not apply to Java deployments, typically in servers, that load and 
    run only trusted code (e.g., code installed by an administrator). (CVE-2021-2341)

  - Vulnerability in the Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component: Library). 
    Supported versions that are affected are Java SE: 7u301, 8u291, 11.0.11, 16.0.1; Oracle GraalVM Enterprise Edition: 
    20.3.2 and 21.1.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via 
    multiple protocols to compromise Java SE, Oracle GraalVM Enterprise Edition. Successful attacks require human 
    interaction from a person other than the attacker. Successful attacks of this vulnerability can result in 
    unauthorized update, insert or delete access to some of Java SE, Oracle GraalVM Enterprise Edition accessible data. 
    This vulnerability applies to Java deployments, typically in clients running sandboxed Java Web Start applications 
    or sandboxed Java applets, that load and run untrusted code (e.g., code that comes from the internet) and rely on 
    the Java sandbox for security. This vulnerability does not apply to Java deployments, typically in servers, that 
    load and run only trusted code (e.g., code installed by an administrator). (CVE-2021-2369)

  - Vulnerability in the Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component: Hotspot). 
    Supported versions that are affected are Java SE: 8u291, 11.0.11, 16.0.1; Oracle GraalVM Enterprise Edition: 
    20.3.2 and 21.1.0. Difficult to exploit vulnerability allows unauthenticated attacker with network access via 
    multiple protocols to compromise Java SE, Oracle GraalVM Enterprise Edition. Successful attacks require human 
    interaction from a person other than the attacker. Successful attacks of this vulnerability can result in takeover 
    of Java SE, Oracle GraalVM Enterprise Edition. This vulnerability applies to Java deployments, typically in
    clients running sandboxed Java Web Start applications or sandboxed Java applets, that load and run untrusted code 
    (e.g., code that comes from the internet) and rely on the Java sandbox for security. This vulnerability does not 
    apply to Java deployments, typically in servers, that load and run only trusted code (e.g., code installed by an 
    administrator). (CVE-2021-2388)

  - Vulnerability in the Java SE product of Oracle Java SE (component: JNDI). The supported version that is affected is 
    Java SE: 7u301. Difficult to exploit vulnerability allows unauthenticated attacker with network access via multiple 
    protocols to compromise Java SE. Successful attacks of this vulnerability can result in unauthorized ability to 
    cause a partial denial of service (partial DOS) of Java SE. This vulnerability applies to Java deployments, 
    typically in clients running sandboxed Java Web Start applications or sandboxed Java applets, that load and run 
    untrusted code (e.g., code that comes from the internet) and rely on the Java sandbox for security. This 
    vulnerability can also be exploited by using APIs in the specified Component, e.g., through a web service which 
    supplies data to the APIs. (CVE-2021-2432)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpujul2021cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujul2021.html#AppendixJAVA");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2021 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-2388");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jre");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jdk");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("sun_java_jre_installed_unix.nasl");
  script_require_keys("Host/Java/JRE/Installed");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_list = ['Oracle Java'];

var app_info = vcf::java::get_app_info(app:app_list);

# 7u301, 8u291, 11.0.11, 16.0.1
var constraints = [
  { 'min_version' : '7.0.0', 'fixed_version' : '7.0.311', 'fixed_display' : 'Upgrade to version 7.0.311 or greater' },
  { 'min_version' : '8.0.291', 'fixed_version' : '8.0.301', 'fixed_display' : 'Upgrade to version 8.0.301 or greater' },
  { 'min_version' : '11.0.0', 'fixed_version' : '11.0.12', 'fixed_display' : 'Upgrade to version 11.0.12 or greater' },
  { 'min_version' : '16.0.0', 'fixed_version' : '16.0.2', 'fixed_display' : 'Upgrade to version 16.0.2 or greater' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
