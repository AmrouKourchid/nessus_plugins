#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(234473);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/16");

  script_cve_id("CVE-2025-21587", "CVE-2025-30691", "CVE-2025-30698");

  script_name(english:"Amazon Corretto Java 17.x < 17.0.15.6.1 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"Amazon Corretto is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Amazon Corretto installed on the remote host is 17 prior to 17.0.15.6.1. It is, therefore, affected by
multiple vulnerabilities as referenced in the corretto-17-2025-Apr-15 advisory.

  - Vulnerability in the Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition product of
    Oracle Java SE (component: JSSE). Supported versions that are affected are Oracle Java SE:8u441,
    8u441-perf, 11.0.26, 17.0.14, 21.0.6, 24; Oracle GraalVM for JDK:17.0.14, 21.0.6, 24; Oracle GraalVM
    Enterprise Edition:20.3.17 and 21.3.13. Difficult to exploit vulnerability allows unauthenticated attacker
    with network access via multiple protocols to compromise Oracle Java SE, Oracle GraalVM for JDK, Oracle
    GraalVM Enterprise Edition. Successful attacks of this vulnerability can result in unauthorized creation,
    deletion or modification access to critical data or all Oracle Java SE, Oracle GraalVM for JDK, Oracle
    GraalVM Enterprise Edition accessible data as well as unauthorized access to critical data or complete
    access to all Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition accessible data.
    Note: This vulnerability can be exploited by using APIs in the specified Component, e.g., through a web
    service which supplies data to the APIs. This vulnerability also applies to Java deployments, typically in
    clients running sandboxed Java Web Start applications or sandboxed Java applets, that load and run
    untrusted code (e.g., code that comes from the internet) and rely on the Java sandbox for security.
    (CVE-2025-21587)

  - Vulnerability in Oracle Java SE (component: Compiler). Supported versions that are affected are Oracle
    Java SE: 21.0.6, 24; Oracle GraalVM for JDK: 21.0.6 and 24. Difficult to exploit vulnerability allows
    unauthenticated attacker with network access via multiple protocols to compromise Oracle Java SE.
    Successful attacks of this vulnerability can result in unauthorized update, insert or delete access to
    some of Oracle Java SE accessible data as well as unauthorized read access to a subset of Oracle Java SE
    accessible data. Note: This vulnerability can be exploited by using APIs in the specified Component, e.g.,
    through a web service which supplies data to the APIs. This vulnerability also applies to Java
    deployments, typically in clients running sandboxed Java Web Start applications or sandboxed Java applets,
    that load and run untrusted code (e.g., code that comes from the internet) and rely on the Java sandbox
    for security. (CVE-2025-30691)

  - Vulnerability in the Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition product of
    Oracle Java SE (component: 2D). Supported versions that are affected are Oracle Java SE: 8u441,
    8u441-perf, 11.0.26, 17.0.14, 21.0.6, 24; Oracle GraalVM for JDK: 17.0.14, 21.0.6, 24; Oracle GraalVM
    Enterprise Edition: 20.3.17 and 21.3.13. Difficult to exploit vulnerability allows unauthenticated
    attacker with network access via multiple protocols to compromise Oracle Java SE, Oracle GraalVM for JDK,
    Oracle GraalVM Enterprise Edition. Successful attacks of this vulnerability can result in unauthorized
    update, insert or delete access to some of Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM
    Enterprise Edition accessible data as well as unauthorized read access to a subset of Oracle Java SE,
    Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition accessible data and unauthorized ability to
    cause a partial denial of service (partial DOS) of Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM
    Enterprise Edition. Note: This vulnerability applies to Java deployments, typically in clients running
    sandboxed Java Web Start applications or sandboxed Java applets, that load and run untrusted code (e.g.,
    code that comes from the internet) and rely on the Java sandbox for security. This vulnerability does not
    apply to Java deployments, typically in servers, that load and run only trusted code (e.g., code installed
    by an administrator). (CVE-2025-30698)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"solution", value:
"Update to Amazon Corretto Java 17.0.15.6.1 or later");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-21587");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/04/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:amazon:corretto");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("amazon_corretto_win_installed.nbin", "amazon_corretto_nix_installed.nbin");
  script_require_keys("installed_sw/Java");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_list = ['Amazon Corretto Java'];
var app_info = vcf::java::get_app_info(app:app_list);

var constraints = [
  { 'min_version' : '17.0', 'fixed_version' : '17.0.15.6.1' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
