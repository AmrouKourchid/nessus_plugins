#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5796. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(209674);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/25");

  script_cve_id("CVE-2023-29659", "CVE-2023-49462", "CVE-2024-41311");
  script_xref(name:"IAVB", value:"2024-B-0073-S");
  script_xref(name:"IAVB", value:"2024-B-0162");

  script_name(english:"Debian dsa-5796 : heif-gdk-pixbuf - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 12 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5796 advisory.

    - -------------------------------------------------------------------------
    Debian Security Advisory DSA-5796-1                   security@debian.org
    https://www.debian.org/security/                       Moritz Muehlenhoff
    October 25, 2024                      https://www.debian.org/security/faq
    - -------------------------------------------------------------------------

    Package        : libheif
    CVE ID         : CVE-2023-29659 CVE-2023-49462 CVE-2024-41311

    Multiple security issues were found in libheif, a library to parse HEIF
    and AVIF files, which could result in denial of service or potentially
    the execution of arbitrary code.

    For the stable distribution (bookworm), these problems have been fixed in
    version 1.15.1-1+deb12u1.

    We recommend that you upgrade your libheif packages.

    For the detailed security status of libheif please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/libheif

    Further information about Debian Security Advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://www.debian.org/security/

    Mailing list: debian-security-announce@lists.debian.org

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/libheif");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-29659");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-49462");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-41311");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bookworm/libheif");
  script_set_attribute(attribute:"solution", value:
"Upgrade the heif-gdk-pixbuf packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-49462");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:heif-gdk-pixbuf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:heif-thumbnailer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libheif-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libheif-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libheif1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:12.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
    {'release': '12.0', 'prefix': 'heif-gdk-pixbuf', 'reference': '1.15.1-1+deb12u1'},
    {'release': '12.0', 'prefix': 'heif-thumbnailer', 'reference': '1.15.1-1+deb12u1'},
    {'release': '12.0', 'prefix': 'libheif-dev', 'reference': '1.15.1-1+deb12u1'},
    {'release': '12.0', 'prefix': 'libheif-examples', 'reference': '1.15.1-1+deb12u1'},
    {'release': '12.0', 'prefix': 'libheif1', 'reference': '1.15.1-1+deb12u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'heif-gdk-pixbuf / heif-thumbnailer / libheif-dev / libheif-examples / etc');
}
