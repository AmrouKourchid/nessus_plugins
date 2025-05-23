#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2019-1327.
#

include('compat.inc');

if (description)
{
  script_id(132322);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/02");

  script_cve_id("CVE-2019-12290", "CVE-2019-18224");
  script_xref(name:"ALAS", value:"2019-1327");

  script_name(english:"Amazon Linux AMI : libidn2 (ALAS-2019-1327)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux AMI host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"idn2_to_ascii_4i in lib/lookup.c in GNU libidn2 before 2.1.1 has a
heap-based buffer overflow via a long domain string. (CVE-2019-18224)

GNU libidn2 before 2.2.0 fails to perform the roundtrip checks
specified in RFC3490 Section 4.2 when converting A-labels to U-labels.
This makes it possible in some circumstances for one domain to
impersonate another. By creating a malicious domain that matches a
target domain except for the inclusion of certain punycoded Unicode
characters (that would be discarded when converted first to a Unicode
label and then back to an ASCII label), arbitrary domains can be
impersonated.(CVE-2019-12290)");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/ALAS-2019-1327.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update libidn2' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-18224");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:idn2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libidn2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libidn2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libidn2-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");
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
if (os_ver != "A")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux AMI", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (rpm_check(release:"ALA", reference:"idn2-2.3.0-1.4.amzn1", allowmaj:TRUE)) flag++;
if (rpm_check(release:"ALA", reference:"libidn2-2.3.0-1.4.amzn1", allowmaj:TRUE)) flag++;
if (rpm_check(release:"ALA", reference:"libidn2-debuginfo-2.3.0-1.4.amzn1", allowmaj:TRUE)) flag++;
if (rpm_check(release:"ALA", reference:"libidn2-devel-2.3.0-1.4.amzn1", allowmaj:TRUE)) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "idn2 / libidn2 / libidn2-debuginfo / libidn2-devel");
}
