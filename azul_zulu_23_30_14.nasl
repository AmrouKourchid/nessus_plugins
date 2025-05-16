#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(209058);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/13");

  script_cve_id(
    "CVE-2023-42950",
    "CVE-2024-21208",
    "CVE-2024-21210",
    "CVE-2024-21217",
    "CVE-2024-21235",
    "CVE-2024-25062"
  );

  script_name(english:"Azul Zulu Java Multiple Vulnerabilities (2024-10-15)");

  script_set_attribute(attribute:"synopsis", value:
"Azul Zulu OpenJDK is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Azul Zulu installed on the remote host is 6 prior to 6.67.0.12 / 7 prior to 7.73.0.14 / 8 prior to
8.81.0.12 / 11 prior to 11.75.12 / 17 prior to 17.53.12 / 21 prior to 21.37.12 / 23 prior to 23.30.14. It is, therefore,
affected by multiple vulnerabilities as referenced in the 2024-10-15 advisory.

  - A use after free issue was addressed with improved memory management. This issue is fixed in Safari 17.2,
    iOS 17.2 and iPadOS 17.2, tvOS 17.2, watchOS 10.2, macOS Sonoma 14.2. Processing maliciously crafted web
    content may lead to arbitrary code execution. (CVE-2023-42950)

  - Vulnerability in the Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition product of
    Oracle Java SE (component: Networking). Supported versions that are affected are Oracle Java SE: 8u421,
    8u421-perf, 11.0.24, 17.0.12, 21.0.4, 23; Oracle GraalVM for JDK: 17.0.12, 21.0.4, 23; Oracle GraalVM
    Enterprise Edition: 20.3.15 and 21.3.11. Difficult to exploit vulnerability allows unauthenticated
    attacker with network access via multiple protocols to compromise Oracle Java SE, Oracle GraalVM for JDK,
    Oracle GraalVM Enterprise Edition. Successful attacks of this vulnerability can result in unauthorized
    ability to cause a partial denial of service (partial DOS) of Oracle Java SE, Oracle GraalVM for JDK,
    Oracle GraalVM Enterprise Edition. Note: This vulnerability applies to Java deployments, typically in
    clients running sandboxed Java Web Start applications or sandboxed Java applets, that load and run
    untrusted code (e.g., code that comes from the internet) and rely on the Java sandbox for security. This
    vulnerability does not apply to Java deployments, typically in servers, that load and run only trusted
    code (e.g., code installed by an administrator). (CVE-2024-21208)

  - Vulnerability in Oracle Java SE (component: Hotspot). Supported versions that are affected are Oracle Java
    SE: 8u421, 8u421-perf, 11.0.24, 17.0.12, 21.0.4 and 23. Difficult to exploit vulnerability allows
    unauthenticated attacker with network access via multiple protocols to compromise Oracle Java SE.
    Successful attacks of this vulnerability can result in unauthorized update, insert or delete access to
    some of Oracle Java SE accessible data. Note: This vulnerability can be exploited by using APIs in the
    specified Component, e.g., through a web service which supplies data to the APIs. This vulnerability also
    applies to Java deployments, typically in clients running sandboxed Java Web Start applications or
    sandboxed Java applets, that load and run untrusted code (e.g., code that comes from the internet) and
    rely on the Java sandbox for security. (CVE-2024-21210)

  - Vulnerability in the Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition product of
    Oracle Java SE (component: Serialization). Supported versions that are affected are Oracle Java SE: 8u421,
    8u421-perf, 11.0.24, 17.0.12, 21.0.4, 23; Oracle GraalVM for JDK: 17.0.12, 21.0.4, 23; Oracle GraalVM
    Enterprise Edition: 20.3.15 and 21.3.11. Difficult to exploit vulnerability allows unauthenticated
    attacker with network access via multiple protocols to compromise Oracle Java SE, Oracle GraalVM for JDK,
    Oracle GraalVM Enterprise Edition. Successful attacks of this vulnerability can result in unauthorized
    ability to cause a partial denial of service (partial DOS) of Oracle Java SE, Oracle GraalVM for JDK,
    Oracle GraalVM Enterprise Edition. Note: This vulnerability can be exploited by using APIs in the
    specified Component, e.g., through a web service which supplies data to the APIs. This vulnerability also
    applies to Java deployments, typically in clients running sandboxed Java Web Start applications or
    sandboxed Java applets, that load and run untrusted code (e.g., code that comes from the internet) and
    rely on the Java sandbox for security. (CVE-2024-21217)

  - Vulnerability in the Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition product of
    Oracle Java SE (component: Hotspot). Supported versions that are affected are Oracle Java SE: 8u421,
    8u421-perf, 11.0.24, 17.0.12, 21.0.4, 23; Oracle GraalVM for JDK: 17.0.12, 21.0.4, 23; Oracle GraalVM
    Enterprise Edition: 20.3.15 and 21.3.11. Difficult to exploit vulnerability allows unauthenticated
    attacker with network access via multiple protocols to compromise Oracle Java SE, Oracle GraalVM for JDK,
    Oracle GraalVM Enterprise Edition. Successful attacks of this vulnerability can result in unauthorized
    update, insert or delete access to some of Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM
    Enterprise Edition accessible data as well as unauthorized read access to a subset of Oracle Java SE,
    Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition accessible data. Note: This vulnerability can be
    exploited by using APIs in the specified Component, e.g., through a web service which supplies data to the
    APIs. This vulnerability also applies to Java deployments, typically in clients running sandboxed Java Web
    Start applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes from
    the internet) and rely on the Java sandbox for security. (CVE-2024-21235)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://docs.azul.com/core/release/october-2024/release-notes");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2024 Azul Zulu OpenJDK Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-42950");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:azul:zulu");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("zulu_java_nix_installed.nbin", "zulu_java_win_installed.nbin");
  script_require_keys("installed_sw/Java");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_list = ['Azul Zulu Java'];
var app_info = vcf::java::get_app_info(app:app_list);
var package_type = app_info['Reported Code'];

var constraints;

if ('SA' == package_type)
{
constraints = [
    { 'min_version' : '6.0.0', 'fixed_version' : '6.67.0.12', 'fixed_display' : 'Upgrade to a version 6.67.0.12 (SA) and above' },
    { 'min_version' : '7.0.0', 'fixed_version' : '7.73.0.14', 'fixed_display' : 'Upgrade to a version 7.73.0.14 (SA) and above' },
    { 'min_version' : '8.0.0', 'fixed_version' : '8.81.0.12', 'fixed_display' : 'Upgrade to a version 8.81.0.12 (SA) and above' },
    { 'min_version' : '11.0.0', 'fixed_version' : '11.75.12', 'fixed_display' : 'Upgrade to a version 11.75.12 (SA) and above' },
    { 'min_version' : '17.0.0', 'fixed_version' : '17.53.12', 'fixed_display' : 'Upgrade to a version 17.53.12 (SA) and above' },
    { 'min_version' : '21.0.0', 'fixed_version' : '21.37.12', 'fixed_display' : 'Upgrade to a version 21.37.12 (SA) and above' },
    { 'min_version' : '23.0.0', 'fixed_version' : '23.30.14', 'fixed_display' : 'Upgrade to a version 23.30.14 (SA) and above' }
  ];
}
else if ('CA' == package_type)
{
  constraints = [
    { 'min_version' : '8.0.0', 'fixed_version' : '8.82.0.21', 'fixed_display' : 'Upgrade to a version 8.82.0.21 (CA) and above' },
    { 'min_version' : '11.0.0', 'fixed_version' : '11.76.21', 'fixed_display' : 'Upgrade to a version 11.76.21 (CA) and above' },
    { 'min_version' : '17.0.0', 'fixed_version' : '17.54.21', 'fixed_display' : 'Upgrade to a version 17.54.21 (CA) and above' },
    { 'min_version' : '21.0.0', 'fixed_version' : '21.38.21', 'fixed_display' : 'Upgrade to a version 21.38.21 (CA) and above' },
    { 'min_version' : '23.0.0', 'fixed_version' : '23.30.13', 'fixed_display' : 'Upgrade to a version 23.30.13 (CA) and above' }
  ];
}

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
