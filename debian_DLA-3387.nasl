#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3387. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(174028);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/22");

  script_cve_id("CVE-2021-3802");

  script_name(english:"Debian dla-3387 : gir1.2-udisks-2.0 - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by a vulnerability as referenced in the dla-3387
advisory.

    -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3387-2                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                         Tobias Frost
    April 10, 2023                                https://wiki.debian.org/LTS
    -------------------------------------------------------------------------

    Package        : udisks2
    Version        : 2.8.1-4+deb10u2
    Debian Bug     : 1034124

    A regression was reported that the fix for CVE-2021-3802 broken mounting
    allow-listed mount option/value pairs, for example errors=remount-ro.

    For Debian 10 buster, this problem has been fixed in version
    2.8.1-4+deb10u2.

    We recommend that you upgrade your udisks2 packages.

    For the detailed security status of udisks2 please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/udisks2

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS
    Attachment:
    signature.asc
    Description: PGP signature

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/udisks2");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3802");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/udisks2");
  script_set_attribute(attribute:"solution", value:
"Upgrade the gir1.2-udisks-2.0 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3802");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/11/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gir1.2-udisks-2.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libudisks2-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libudisks2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udisks2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udisks2-bcache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udisks2-btrfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udisks2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udisks2-lvm2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udisks2-vdo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udisks2-zram");
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
    {'release': '10.0', 'prefix': 'gir1.2-udisks-2.0', 'reference': '2.8.1-4+deb10u2'},
    {'release': '10.0', 'prefix': 'libudisks2-0', 'reference': '2.8.1-4+deb10u2'},
    {'release': '10.0', 'prefix': 'libudisks2-dev', 'reference': '2.8.1-4+deb10u2'},
    {'release': '10.0', 'prefix': 'udisks2', 'reference': '2.8.1-4+deb10u2'},
    {'release': '10.0', 'prefix': 'udisks2-bcache', 'reference': '2.8.1-4+deb10u2'},
    {'release': '10.0', 'prefix': 'udisks2-btrfs', 'reference': '2.8.1-4+deb10u2'},
    {'release': '10.0', 'prefix': 'udisks2-doc', 'reference': '2.8.1-4+deb10u2'},
    {'release': '10.0', 'prefix': 'udisks2-lvm2', 'reference': '2.8.1-4+deb10u2'},
    {'release': '10.0', 'prefix': 'udisks2-vdo', 'reference': '2.8.1-4+deb10u2'},
    {'release': '10.0', 'prefix': 'udisks2-zram', 'reference': '2.8.1-4+deb10u2'}
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
    severity   : SECURITY_WARNING,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'gir1.2-udisks-2.0 / libudisks2-0 / libudisks2-dev / udisks2 / etc');
}
