#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2011-6777.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(54294);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/02");
  script_xref(name:"FEDORA", value:"2011-6777");

  script_name(english:"Fedora 13 : postfix-2.7.4-1.fc13 (2011-6777)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This is an update that fixes memory corruption in Postfix SMTP server
Cyrus SASL support (CVE-2011-1720). For original upstream announcement
see: http://archives.neohapsis.com/archives/postfix/2011-05/0208.html

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # http://web.archive.org/web/20110731173805/http://archives.neohapsis.com:80/archives/postfix/2011-05/0208.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?17ceb8e4");
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-May/060215.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7d228cd8");
  script_set_attribute(attribute:"solution", value:
"Update the affected postfix package.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:postfix");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Fedora Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2011-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Fedora" >!< release) audit(AUDIT_OS_NOT, "Fedora");
os_ver = eregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! ereg(pattern:"^13([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 13.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC13", reference:"postfix-2.7.4-1.fc13")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "postfix");
}
