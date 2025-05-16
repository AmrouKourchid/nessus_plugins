#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2025-2812.
##

include('compat.inc');

if (description)
{
  script_id(233710);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/01");

  script_cve_id("CVE-2021-24122", "CVE-2023-42795", "CVE-2025-24813");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2025/04/22");
  script_xref(name:"IAVA", value:"2020-A-0570-S");
  script_xref(name:"IAVA", value:"2023-A-0534-S");
  script_xref(name:"IAVA", value:"2025-A-0156");

  script_name(english:"Amazon Linux 2 : tomcat (ALAS-2025-2812)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of tomcat installed on the remote host is prior to 7.0.76-10. It is, therefore, affected by multiple
vulnerabilities as referenced in the ALAS2-2025-2812 advisory.

    When serving resources from a network location using the NTFS file system, Apache Tomcat versions
    10.0.0-M1 to 10.0.0-M9, 9.0.0.M1 to 9.0.39, 8.5.0 to 8.5.59 and 7.0.0 to 7.0.106 were susceptible to JSP
    source code disclosure in some configurations. The root cause was the unexpected behaviour of the JRE API
    File.getCanonicalPath() which in turn was caused by the inconsistent behaviour of the Windows API
    (FindFirstFileW) in some circumstances. (CVE-2021-24122)

    Incomplete Cleanup vulnerability in Apache Tomcat. When recycling various internal objects in Apache
    Tomcat from 11.0.0-M1 through 11.0.0-M11, from 10.1.0-M1 through 10.1.13, from 9.0.0-M1 through 9.0.80 and
    from 8.5.0 through 8.5.93, an error could cause Tomcat to skip some parts of the recycling process leading
    to information leaking from the current request/response to the next. Users are recommended to upgrade to
    version 11.0.0-M12 onwards, 10.1.14 onwards, 9.0.81 onwards or 8.5.94 onwards, which fixes the issue.
    (CVE-2023-42795)

    Path Equivalence: 'file.Name' (Internal Dot) leading to Remote Code Execution and/or Information
    disclosure and/or malicious content added to uploaded files via write enabled Default Servlet in Apache
    Tomcat.

    This issue affects Apache Tomcat: from 11.0.0-M1 through 11.0.2, from 10.1.0-M1 through 10.1.34, from
    9.0.0.M1 through 9.0.98.

    If all of the following were true, a malicious user was able to view       security sensitive files and/or
    inject content into those files:- writes enabled for the default servlet (disabled by default)- support
    for partial PUT (enabled by default)- a target URL for security sensitive uploads that was a sub-directory
    of a target URL for public uploads- attacker knowledge of the names of security sensitive files being
    uploaded- the security sensitive files also being uploaded via partial PUT

    If all of the following were true, a malicious user was able to       perform remote code execution:-
    writes enabled for the default servlet (disabled by default)- support for partial PUT (enabled by
    default)- application was using Tomcat's file based session persistence with the default storage location-
    application included a library that may be leveraged in a deserialization attack

    Users are recommended to upgrade to version 11.0.3, 10.1.35 or 9.0.98, which fixes the issue.

    More justification and the patch links are available for all versions here:[1]
    https://tomcat.apache.org/security-11.html[2] https://tomcat.apache.org/security-10.html[3]
    https://tomcat.apache.org/security-9.html (CVE-2025-24813)

Tenable has extracted the preceding description block directly from the tested product security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALAS-2025-2812.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-24122.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-42795.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2025-24813.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update tomcat' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-24122");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2025-24813");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/03/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat-admin-webapps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat-docs-webapp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat-el-2.2-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat-jsp-2.2-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat-jsvc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat-servlet-3.0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat-webapps");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var alas_release = get_kb_item("Host/AmazonLinux/release");
if (isnull(alas_release) || !strlen(alas_release)) audit(AUDIT_OS_NOT, "Amazon Linux");
var os_ver = pregmatch(pattern: "^AL(A|\d+|-\d+)", string:alas_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "2")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var pkgs = [
    {'reference':'tomcat-7.0.76-10.amzn2.0.10', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tomcat-admin-webapps-7.0.76-10.amzn2.0.10', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tomcat-docs-webapp-7.0.76-10.amzn2.0.10', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tomcat-el-2.2-api-7.0.76-10.amzn2.0.10', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tomcat-javadoc-7.0.76-10.amzn2.0.10', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tomcat-jsp-2.2-api-7.0.76-10.amzn2.0.10', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tomcat-jsvc-7.0.76-10.amzn2.0.10', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tomcat-lib-7.0.76-10.amzn2.0.10', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tomcat-servlet-3.0-api-7.0.76-10.amzn2.0.10', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tomcat-webapps-7.0.76-10.amzn2.0.10', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  var cves = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['cves'])) cves = package_array['cves'];
  if (reference && _release && (!exists_check || rpm_exists(release:_release, rpm:exists_check))) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj, cves:cves)) flag++;
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tomcat / tomcat-admin-webapps / tomcat-docs-webapp / etc");
}
