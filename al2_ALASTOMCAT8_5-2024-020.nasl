#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALASTOMCAT8.5-2024-020.
##

include('compat.inc');

if (description)
{
  script_id(205722);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/11");

  script_cve_id("CVE-2024-34750");
  script_xref(name:"IAVA", value:"2024-A-0393-S");

  script_name(english:"Amazon Linux 2 : tomcat (ALASTOMCAT8.5-2024-020)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of tomcat installed on the remote host is prior to 8.5.100-1. It is, therefore, affected by a vulnerability
as referenced in the ALAS2TOMCAT8.5-2024-020 advisory.

    Improper Handling of Exceptional Conditions, Uncontrolled Resource Consumption vulnerability in Apache
    Tomcat. When processing an HTTP/2 stream, Tomcat did not handle some cases of excessive HTTP headers
    correctly. This led to a miscounting of active HTTP/2 streams which in turn led to the use of an incorrect
    infinite timeout which allowed connections to remain open which should have been closed.

    This issue affects Apache Tomcat: from 11.0.0-M1 through 11.0.0-M20, from 10.1.0-M1 through 10.1.24, from
    9.0.0-M1 through 9.0.89.

    Users are recommended to upgrade to version 11.0.0-M21, 10.1.25 or 9.0.90, which fixes the issue.
    (CVE-2024-34750)

Tenable has extracted the preceding description block directly from the tested product security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALASTOMCAT8.5-2024-020.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-34750.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update tomcat' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-34750");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/06/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat-admin-webapps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat-docs-webapp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat-el-3.0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat-jsp-2.3-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat-jsvc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat-servlet-3.1-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat-webapps");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

var REPOS_FOUND = TRUE;
var extras_list = get_kb_item("Host/AmazonLinux/extras_label_list");
if (isnull(extras_list)) REPOS_FOUND = FALSE;
var repository = '"amzn2extra-tomcat8.5"';
if (REPOS_FOUND && (repository >!< extras_list)) exit(0, AFFECTED_REPO_NOT_ENABLED);

var pkgs = [
    {'reference':'tomcat-8.5.100-1.amzn2.0.2', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat8.5'},
    {'reference':'tomcat-admin-webapps-8.5.100-1.amzn2.0.2', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat8.5'},
    {'reference':'tomcat-docs-webapp-8.5.100-1.amzn2.0.2', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat8.5'},
    {'reference':'tomcat-el-3.0-api-8.5.100-1.amzn2.0.2', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat8.5'},
    {'reference':'tomcat-javadoc-8.5.100-1.amzn2.0.2', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat8.5'},
    {'reference':'tomcat-jsp-2.3-api-8.5.100-1.amzn2.0.2', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat8.5'},
    {'reference':'tomcat-jsvc-8.5.100-1.amzn2.0.2', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat8.5'},
    {'reference':'tomcat-lib-8.5.100-1.amzn2.0.2', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat8.5'},
    {'reference':'tomcat-servlet-3.1-api-8.5.100-1.amzn2.0.2', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat8.5'},
    {'reference':'tomcat-webapps-8.5.100-1.amzn2.0.2', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat8.5'}
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
  var extra = rpm_report_get();
  if (!REPOS_FOUND) extra = rpm_report_get() + report_repo_caveat();
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : extra
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tomcat / tomcat-admin-webapps / tomcat-docs-webapp / etc");
}
