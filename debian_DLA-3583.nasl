#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3583. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(181858);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/22");

  script_cve_id("CVE-2023-29499", "CVE-2023-32611", "CVE-2023-32665");

  script_name(english:"Debian dla-3583 : libglib2.0-0 - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3583 advisory.

    -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3583-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/               Santiago Ruano Rincn
    September 25, 2023                            https://wiki.debian.org/LTS
    -------------------------------------------------------------------------

    Package        : glib2.0
    Version        : 2.58.3-2+deb10u5
    CVE ID         : CVE-2023-29499 CVE-2023-32611 CVE-2023-32665

    Several security vulnerabilities were found in GLib, a general-purpose utility
    library, used by projects such as GTK+, GIMP, and GNOME.

    CVE-2023-29499

        GVariant deserialization fails to validate that the input conforms to the
        expected format, leading to denial of service.

    CVE-2023-32611

        GVariant deserialization is vulnerable to a slowdown issue where a crafted
        GVariant can cause excessive processing, leading to denial of service.

    CVE-2023-32665

        GVariant deserialization is vulnerable to an exponential blowup issue where
        a crafted GVariant can cause excessive processing, leading to denial of
        service.


    For Debian 10 buster, these problems have been fixed in version
    2.58.3-2+deb10u5.

    We recommend that you upgrade your glib2.0 packages.

    For the detailed security status of glib2.0 please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/glib2.0

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS
    Attachment:
    signature.asc
    Description: PGP signature

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/glib2.0");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-29499");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-32611");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-32665");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/glib2.0");
  script_set_attribute(attribute:"solution", value:
"Upgrade the libglib2.0-0 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-29499");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/06/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libglib2.0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libglib2.0-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libglib2.0-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libglib2.0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libglib2.0-dev-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libglib2.0-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libglib2.0-tests");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(10)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 10.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'libglib2.0-0', 'reference': '2.58.3-2+deb10u5'},
    {'release': '10.0', 'prefix': 'libglib2.0-bin', 'reference': '2.58.3-2+deb10u5'},
    {'release': '10.0', 'prefix': 'libglib2.0-data', 'reference': '2.58.3-2+deb10u5'},
    {'release': '10.0', 'prefix': 'libglib2.0-dev', 'reference': '2.58.3-2+deb10u5'},
    {'release': '10.0', 'prefix': 'libglib2.0-dev-bin', 'reference': '2.58.3-2+deb10u5'},
    {'release': '10.0', 'prefix': 'libglib2.0-doc', 'reference': '2.58.3-2+deb10u5'},
    {'release': '10.0', 'prefix': 'libglib2.0-tests', 'reference': '2.58.3-2+deb10u5'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libglib2.0-0 / libglib2.0-bin / libglib2.0-data / libglib2.0-dev / etc');
}
