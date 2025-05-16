#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2024-2460.
##

include('compat.inc');

if (description)
{
  script_id(190690);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/11");

  script_cve_id("CVE-2023-40167");

  script_name(english:"Amazon Linux 2 : jetty (ALAS-2024-2460)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"It is, therefore, affected by a vulnerability as referenced in the ALAS2-2024-2460 advisory.

    Jetty is a Java based web server and servlet engine. Prior to versions 9.4.52, 10.0.16, 11.0.16, and
    12.0.1, Jetty accepts the `+` character proceeding the content-length value in a HTTP/1 header field.
    This is more permissive than allowed by the RFC and other servers routinely reject such requests with 400
    responses.  There is no known exploit scenario, but it is conceivable that request smuggling could result
    if jetty is used in combination with a server that does not close the connection after sending such a 400
    response. Versions 9.4.52, 10.0.16, 11.0.16, and 12.0.1 contain a patch for this issue. There is no
    workaround as there is no known exploit scenario. (CVE-2023-40167)

Tenable has extracted the preceding description block directly from the tested product security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALAS-2024-2460.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-40167.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update jetty' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-40167");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/09/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:jetty-annotations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:jetty-ant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:jetty-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:jetty-continuation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:jetty-deploy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:jetty-http");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:jetty-io");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:jetty-jaas");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:jetty-jaspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:jetty-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:jetty-jmx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:jetty-jndi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:jetty-jsp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:jetty-jspc-maven-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:jetty-maven-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:jetty-monitor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:jetty-plus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:jetty-project");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:jetty-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:jetty-rewrite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:jetty-runner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:jetty-security");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:jetty-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:jetty-servlet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:jetty-servlets");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:jetty-start");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:jetty-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:jetty-util-ajax");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:jetty-webapp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:jetty-websocket-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:jetty-websocket-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:jetty-websocket-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:jetty-websocket-parent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:jetty-websocket-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:jetty-websocket-servlet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:jetty-xml");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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

var pkgs = [
    {'reference':'jetty-annotations-9.0.3-8.amzn2.0.3', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'jetty-ant-9.0.3-8.amzn2.0.3', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'jetty-client-9.0.3-8.amzn2.0.3', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'jetty-continuation-9.0.3-8.amzn2.0.3', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'jetty-deploy-9.0.3-8.amzn2.0.3', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'jetty-http-9.0.3-8.amzn2.0.3', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'jetty-io-9.0.3-8.amzn2.0.3', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'jetty-jaas-9.0.3-8.amzn2.0.3', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'jetty-jaspi-9.0.3-8.amzn2.0.3', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'jetty-javadoc-9.0.3-8.amzn2.0.3', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'jetty-jmx-9.0.3-8.amzn2.0.3', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'jetty-jndi-9.0.3-8.amzn2.0.3', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'jetty-jsp-9.0.3-8.amzn2.0.3', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'jetty-jspc-maven-plugin-9.0.3-8.amzn2.0.3', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'jetty-maven-plugin-9.0.3-8.amzn2.0.3', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'jetty-monitor-9.0.3-8.amzn2.0.3', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'jetty-plus-9.0.3-8.amzn2.0.3', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'jetty-project-9.0.3-8.amzn2.0.3', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'jetty-proxy-9.0.3-8.amzn2.0.3', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'jetty-rewrite-9.0.3-8.amzn2.0.3', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'jetty-runner-9.0.3-8.amzn2.0.3', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'jetty-security-9.0.3-8.amzn2.0.3', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'jetty-server-9.0.3-8.amzn2.0.3', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'jetty-servlet-9.0.3-8.amzn2.0.3', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'jetty-servlets-9.0.3-8.amzn2.0.3', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'jetty-start-9.0.3-8.amzn2.0.3', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'jetty-util-9.0.3-8.amzn2.0.3', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'jetty-util-ajax-9.0.3-8.amzn2.0.3', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'jetty-webapp-9.0.3-8.amzn2.0.3', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'jetty-websocket-api-9.0.3-8.amzn2.0.3', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'jetty-websocket-client-9.0.3-8.amzn2.0.3', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'jetty-websocket-common-9.0.3-8.amzn2.0.3', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'jetty-websocket-parent-9.0.3-8.amzn2.0.3', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'jetty-websocket-server-9.0.3-8.amzn2.0.3', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'jetty-websocket-servlet-9.0.3-8.amzn2.0.3', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'jetty-xml-9.0.3-8.amzn2.0.3', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "jetty-annotations / jetty-ant / jetty-client / etc");
}
