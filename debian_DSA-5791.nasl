#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5791. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(208931);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/13");

  script_cve_id("CVE-2023-33733");

  script_name(english:"Debian dsa-5791 : python-reportlab-doc - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 12 host has packages installed that are affected by a vulnerability as referenced in the dsa-5791
advisory.

    - -------------------------------------------------------------------------
    Debian Security Advisory DSA-5791-1                   security@debian.org
    https://www.debian.org/security/                       Moritz Muehlenhoff
    October 13, 2024                      https://www.debian.org/security/faq
    - -------------------------------------------------------------------------

    Package        : python-reportlab
    CVE ID         : CVE-2023-33733

    Elyas Damej discovered that a sandbox mechanism in ReportLab, a Python
    library to create PDF documents, could be bypassed which may result in
    the execution of arbitrary code when converting malformed HTML to a PDF
    document.

    For the stable distribution (bookworm), this problem has been fixed in
    version 3.6.12-1+deb12u1.

    We recommend that you upgrade your python-reportlab packages.

    For the detailed security status of python-reportlab please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/python-reportlab

    Further information about Debian Security Advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://www.debian.org/security/

    Mailing list: debian-security-announce@lists.debian.org

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://security-tracker.debian.org/tracker/source-package/python-reportlab
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cca36a40");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-33733");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bookworm/python-reportlab");
  script_set_attribute(attribute:"solution", value:
"Upgrade the python-reportlab-doc packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-33733");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/06/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-reportlab-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-renderpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-reportlab");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-reportlab-accel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:12.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var debian_release = get_kb_item('Host/Debian/release');
if ( isnull(debian_release) ) audit(AUDIT_OS_NOT, 'Debian');
debian_release = chomp(debian_release);
if (! preg(pattern:"^(12)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 12.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '12.0', 'prefix': 'python-reportlab-doc', 'reference': '3.6.12-1+deb12u1'},
    {'release': '12.0', 'prefix': 'python3-renderpm', 'reference': '3.6.12-1+deb12u1'},
    {'release': '12.0', 'prefix': 'python3-reportlab', 'reference': '3.6.12-1+deb12u1'},
    {'release': '12.0', 'prefix': 'python3-reportlab-accel', 'reference': '3.6.12-1+deb12u1'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var _release = NULL;
  var prefix = NULL;
  var reference = NULL;
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['prefix'])) prefix = package_array['prefix'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (_release && prefix && reference) {
    if (deb_check(release:_release, prefix:prefix, reference:reference)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'python-reportlab-doc / python3-renderpm / python3-reportlab / etc');
}
