#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2010-14351.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(49162);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/02");
  script_xref(name:"FEDORA", value:"2010-14351");

  script_name(english:"Fedora 13 : sunbird-1.0-0.28.b2pre.fc13 / thunderbird-3.1.3-1.fc13 (2010-14351)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"Update to new upstream Thunderbird version 3.1.3, fixing multiple
security issues detailed in the upstream advisory:
http://www.mozilla.org/security
/known-vulnerabilities/thunderbird31.html#thunderbird3.1.3 Update also
includes sunbird package rebuilt against new version of Thunderbird.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/");
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-September/047238.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d1e856d3");
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-September/047239.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fc0787f5");
  script_set_attribute(attribute:"solution", value:
"Update the affected sunbird and / or thunderbird packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:sunbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:thunderbird");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Fedora Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2010-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (rpm_check(release:"FC13", reference:"sunbird-1.0-0.28.b2pre.fc13")) flag++;
if (rpm_check(release:"FC13", reference:"thunderbird-3.1.3-1.fc13")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "sunbird / thunderbird");
}
