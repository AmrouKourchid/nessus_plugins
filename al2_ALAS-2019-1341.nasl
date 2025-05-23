#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2019-1341.
#

include('compat.inc');

if (description)
{
  script_id(130400);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/16");

  script_cve_id("CVE-2019-10092", "CVE-2019-10097", "CVE-2019-10098");
  script_xref(name:"ALAS", value:"2019-1341");

  script_name(english:"Amazon Linux 2 : httpd (ALAS-2019-1341)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"A cross-site scripting vulnerability was found in Apache httpd,
affecting the mod_proxy error page. Under certain circumstances, a
crafted link could inject content into the HTML displayed in the error
page, potentially leading to client-side exploitation.(CVE-2019-10092)

A vulnerability was discovered in Apache httpd, in mod_remoteip. A
trusted proxy using the 'PROXY' protocol could send specially crafted
headers that can cause httpd to experience a stack buffer overflow or
NULL pointer dereference, leading to a crash or other potential
consequences.\n\nThis issue could only be exploited by configured
trusted intermediate proxy servers. HTTP clients such as browsers
could not exploit the vulnerability.(CVE-2019-10097)

A vulnerability was discovered in Apache httpd, in mod_rewrite.
Certain self-referential mod_rewrite rules could be fooled by encoded
newlines, causing them to redirect to an unexpected location. An
attacker could abuse this flaw in a phishing attack or as part of a
client-side attack on browsers.(CVE-2019-10098)");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALAS-2019-1341.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update httpd' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-10097");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:httpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:httpd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:httpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:httpd-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:httpd-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:httpd-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mod_ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mod_md");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mod_proxy_html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mod_session");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mod_ssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/AmazonLinux/release");
if (isnull(release) || !strlen(release)) audit(AUDIT_OS_NOT, "Amazon Linux");
os_ver = pregmatch(pattern: "^AL(A|\d)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "2")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (rpm_check(release:"AL2", reference:"httpd-2.4.41-1.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"httpd-debuginfo-2.4.41-1.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"httpd-devel-2.4.41-1.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"httpd-filesystem-2.4.41-1.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"httpd-manual-2.4.41-1.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"httpd-tools-2.4.41-1.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"mod_ldap-2.4.41-1.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"mod_md-2.4.41-1.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"mod_proxy_html-2.4.41-1.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"mod_session-2.4.41-1.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"mod_ssl-2.4.41-1.amzn2.0.1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "httpd / httpd-debuginfo / httpd-devel / httpd-filesystem / etc");
}
