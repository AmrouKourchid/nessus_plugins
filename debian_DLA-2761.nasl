#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-2761. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153481);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/24");

  script_name(english:"Debian DLA-2761-1 : openssl1.0 - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 9 host has packages installed that are affected by a vulnerability as referenced in the dla-2761
advisory.

    The legacy 1.0 version of OpenSSL, a cryptography library for secure communication, fails to validate
    alternate trust chains in some conditions. In particular this breaks connecting to servers that use Let's
    Encrypt certificates, starting 2021-10-01. For Debian 9 stretch, this problem has been fixed in version
    1.0.2u-1~deb9u5. We recommend that you upgrade your openssl1.0 packages. For the detailed security status
    of openssl1.0 please refer to its security tracker page at: https://security-
    tracker.debian.org/tracker/openssl1.0 Further information about Debian LTS security advisories, how to
    apply these updates to your system and frequently asked questions can be found at:
    https://wiki.debian.org/LTS

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/openssl1.0");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2021/dla-2761");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/openssl1.0");
  script_set_attribute(attribute:"solution", value:
"Upgrade the openssl1.0 packages.

For Debian 9 stretch, this problem has been fixed in version 1.0.2u-1~deb9u5.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libssl1.0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libssl1.0.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(9)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 9.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '9.0', 'prefix': 'libssl1.0-dev', 'reference': '1.0.2u-1~deb9u5'},
    {'release': '9.0', 'prefix': 'libssl1.0.2', 'reference': '1.0.2u-1~deb9u5'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libssl1.0-dev / libssl1.0.2');
}
