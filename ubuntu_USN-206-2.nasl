#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-206-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(20623);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/02");
  script_bugtraq_id(15117);
  script_xref(name:"USN", value:"206-2");

  script_name(english:"Ubuntu 4.10 / 5.04 / 5.10 : lynx regression fix (USN-206-2)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security-related patch.");
  script_set_attribute(attribute:"description", value:
"USN-206-1 fixed a security vulnerability in lynx. Unfortunately the
fix contained an error that caused lynx to crash under certain
circumstances. The updated packages fix this.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"solution", value:
"Update the affected lynx package.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/10/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/01/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lynx");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:4.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2005-2019 Canonical, Inc. / NASL script (C) 2006-2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("ubuntu.inc");
include("misc_func.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/Ubuntu/release");
if ( isnull(release) ) audit(AUDIT_OS_NOT, "Ubuntu");
release = chomp(release);
if (! ereg(pattern:"^(4\.10|5\.04|5\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 4.10 / 5.04 / 5.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"4.10", pkgname:"lynx", pkgver:"2.8.5-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"lynx", pkgver:"2.8.5-2ubuntu0.5.04.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"lynx", pkgver:"2.8.5-2ubuntu0.5.10.1")) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "lynx");
}
