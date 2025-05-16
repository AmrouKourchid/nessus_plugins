#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3354. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(172141);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/22");

  script_cve_id("CVE-2019-19907", "CVE-2022-26562");

  script_name(english:"Debian dla-3354 : kopano-archiver - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3354 advisory.

    - -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3354-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/               Emilio Pozuelo Monfort
    March 06, 2023                                https://wiki.debian.org/LTS
    - -------------------------------------------------------------------------

    Package        : kopanocore
    Version        : 8.7.0-3+deb10u1
    CVE ID         : CVE-2019-19907 CVE-2022-26562
    Debian Bug     : 1016973

    Several issues were found in Kopano Collaboration Platform, a groupware
    solution, which could cause denial of service or unauthorized access.

    For Debian 10 buster, these problems have been fixed in version
    8.7.0-3+deb10u1.

    We recommend that you upgrade your kopanocore packages.

    For the detailed security status of kopanocore please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/kopanocore

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/kopanocore");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-19907");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-26562");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/kopanocore");
  script_set_attribute(attribute:"solution", value:
"Upgrade the kopano-archiver packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-26562");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kopano-archiver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kopano-backup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kopano-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kopano-contacts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kopano-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kopano-dagent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kopano-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kopano-gateway");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kopano-ical");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kopano-l10n");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kopano-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kopano-monitor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kopano-presence");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kopano-search");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kopano-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kopano-spamd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kopano-spooler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kopano-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-mapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-kopano");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-mapi");
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
    {'release': '10.0', 'prefix': 'kopano-archiver', 'reference': '8.7.0-3+deb10u1'},
    {'release': '10.0', 'prefix': 'kopano-backup', 'reference': '8.7.0-3+deb10u1'},
    {'release': '10.0', 'prefix': 'kopano-common', 'reference': '8.7.0-3+deb10u1'},
    {'release': '10.0', 'prefix': 'kopano-contacts', 'reference': '8.7.0-3+deb10u1'},
    {'release': '10.0', 'prefix': 'kopano-core', 'reference': '8.7.0-3+deb10u1'},
    {'release': '10.0', 'prefix': 'kopano-dagent', 'reference': '8.7.0-3+deb10u1'},
    {'release': '10.0', 'prefix': 'kopano-dev', 'reference': '8.7.0-3+deb10u1'},
    {'release': '10.0', 'prefix': 'kopano-gateway', 'reference': '8.7.0-3+deb10u1'},
    {'release': '10.0', 'prefix': 'kopano-ical', 'reference': '8.7.0-3+deb10u1'},
    {'release': '10.0', 'prefix': 'kopano-l10n', 'reference': '8.7.0-3+deb10u1'},
    {'release': '10.0', 'prefix': 'kopano-libs', 'reference': '8.7.0-3+deb10u1'},
    {'release': '10.0', 'prefix': 'kopano-monitor', 'reference': '8.7.0-3+deb10u1'},
    {'release': '10.0', 'prefix': 'kopano-presence', 'reference': '8.7.0-3+deb10u1'},
    {'release': '10.0', 'prefix': 'kopano-search', 'reference': '8.7.0-3+deb10u1'},
    {'release': '10.0', 'prefix': 'kopano-server', 'reference': '8.7.0-3+deb10u1'},
    {'release': '10.0', 'prefix': 'kopano-spamd', 'reference': '8.7.0-3+deb10u1'},
    {'release': '10.0', 'prefix': 'kopano-spooler', 'reference': '8.7.0-3+deb10u1'},
    {'release': '10.0', 'prefix': 'kopano-utils', 'reference': '8.7.0-3+deb10u1'},
    {'release': '10.0', 'prefix': 'php-mapi', 'reference': '8.7.0-3+deb10u1'},
    {'release': '10.0', 'prefix': 'python3-kopano', 'reference': '8.7.0-3+deb10u1'},
    {'release': '10.0', 'prefix': 'python3-mapi', 'reference': '8.7.0-3+deb10u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kopano-archiver / kopano-backup / kopano-common / kopano-contacts / etc');
}
