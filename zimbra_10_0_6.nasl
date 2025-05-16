#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(192099);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/25");

  script_cve_id(
    "CVE-2022-21449",
    "CVE-2022-21476",
    "CVE-2023-21930",
    "CVE-2023-48432"
  );
  script_xref(name:"IAVA", value:"2024-A-0145-S");

  script_name(english:"Zimbra Collaboration Server 8.8.x < 8.8.15 Patch 45, 9.x < 9.0.0 Patch 38, 10.0.x < 10.0.6 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a web application that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, Zimbra Collaboration Server is affected by multiple vulnerabilities
including:

  - Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition
    product of Oracle Java SE (component: Libraries). Supported versions that
    are affected are Oracle Java SE: 7u331, 8u321, 11.0.14, 17.0.2, 18; Oracle
    GraalVM Enterprise Edition: 20.3.5, 21.3.1 and 22.0.0.2. Easily exploitable
    vulnerability allows unauthenticated attacker with network access via
    multiple protocols to compromise Oracle Java SE, Oracle GraalVM Enterprise
    Edition. Successful attacks of this vulnerability can result in unauthorized
    access to critical data or complete access to all Oracle Java SE, Oracle
    GraalVM Enterprise Edition accessible data. Note: This vulnerability applies
    to Java deployments, typically in clients running sandboxed Java Web Start
    applications or sandboxed Java applets, that load and run untrusted code
    (e.g., code that comes from the internet) and rely on the Java sandbox for
    security. This vulnerability can also be exploited by using APIs in the
    specified Component, e.g., through a web service which supplies data to the
    APIs. (CVE-2022-21476)

  - Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition
    product of Oracle Java SE (component: Libraries). Supported versions that
    are affected are Oracle Java SE: 17.0.2 and 18; Oracle GraalVM Enterprise
    Edition: 21.3.1 and 22.0.0.2. Easily exploitable vulnerability allows
    unauthenticated attacker with network access via multiple protocols to
    compromise Oracle Java SE, Oracle GraalVM Enterprise Edition. Successful
    attacks of this vulnerability can result in unauthorized creation, deletion
    or modification access to critical data or all Oracle Java SE, Oracle
    GraalVM Enterprise Edition accessible data. Note: This vulnerability applies
    to Java deployments, typically in clients running sandboxed Java Web Start
    applications or sandboxed Java applets, that load and run untrusted code
    (e.g., code that comes from the internet) and rely on the Java sandbox for
    security. This vulnerability can also be exploited by using APIs in the
    specified Component, e.g., through a web service which supplies data to the
    APIs. (CVE-2022-21449)

  -	Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition
    product of Oracle Java SE (component: JSSE). Supported versions that are 
    affected are Oracle Java SE: 8u361, 8u361-perf, 11.0.18, 17.0.6, 20; Oracle
    GraalVM Enterprise Edition: 20.3.9, 21.3.5 and 22.3.1. Difficult to exploit
    vulnerability allows unauthenticated attacker with network access via TLS
    to compromise Oracle Java SE, Oracle GraalVM Enterprise Edition. Successful
    attacks of this vulnerability can result in unauthorized creation, deletion
    or modification access to critical data or all Oracle Java SE, Oracle
    GraalVM Enterprise Edition accessible data as well as unauthorized access to
    critical data or complete access to all Oracle Java SE, Oracle GraalVM
    Enterprise Edition accessible data. Note: This vulnerability applies to Java
    deployments, typically in clients running sandboxed Java Web Start
    applications or sandboxed Java applets, that load and run untrusted code
    (e.g., code that comes from the internet) and rely on the Java sandbox for
    security. This vulnerability can also be exploited by using APIs in the
    specified Component, e.g., through a web service which supplies data to the
    APIs. (CVE-2023-21930)

  -	An issue was discovered in Zimbra Collaboration (ZCS) 8.8.15, 9.0, and 10.0.
    XSS, with resultant session stealing, can occur via JavaScript code in a
    link (for a webmail redirection endpoint) within en email message, e.g., if
    a victim clicks on that link within Zimbra webmail. (CVE-2023-48432)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://wiki.zimbra.com/wiki/Zimbra_Releases/10.0.6");
  script_set_attribute(attribute:"see_also", value:"https://wiki.zimbra.com/wiki/Zimbra_Releases/9.0.0/P38");
  script_set_attribute(attribute:"see_also", value:"https://wiki.zimbra.com/wiki/Zimbra_Releases/8.8.15/P45");
  script_set_attribute(attribute:"see_also", value:"https://wiki.zimbra.com/wiki/Security_Center");
  script_set_attribute(attribute:"see_also", value:"https://wiki.zimbra.com/wiki/Zimbra_Security_Advisories");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 8.8.15 Patch 45, 9.0.0 Patch 38, 10.0.6, or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-21476");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-21930");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/12/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/12/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/03/14");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zimbra:collaboration_suite");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("zimbra_web_detect.nbin", "zimbra_nix_installed.nbin");
  script_require_keys("installed_sw/zimbra_zcs");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::zimbra::combined_get_app_info();

var constraints = [
  {'min_version':'8.8', 'max_version':'8.8.15', 'fixed_display':'8.8.15 Patch 45', 'Patch':'45'},
  {'min_version':'9.0', 'max_version':'9.0.0', 'fixed_display':'9.0.0 Patch 38', 'Patch':'38'},
  {'min_version':'10.0', 'fixed_version':'10.0.6', 'fixed_display':'10.0.6'}
];

vcf::zimbra::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  flags:{'xss':TRUE}
);
