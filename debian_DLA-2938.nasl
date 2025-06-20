#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-2938. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158698);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/06");

  script_cve_id("CVE-2022-21716");

  script_name(english:"Debian DLA-2938-1 : twisted - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 9 host has packages installed that are affected by a vulnerability as referenced in the dla-2938
advisory.

  - Twisted is an event-based framework for internet applications, supporting Python 3.6+. Prior to 22.2.0,
    Twisted SSH client and server implement is able to accept an infinite amount of data for the peer's SSH
    version identifier. This ends up with a buffer using all the available memory. The attach is a simple as
    `nc -rv localhost 22 < /dev/zero`. A patch is available in version 22.2.0. There are currently no known
    workarounds. (CVE-2022-21716)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2022/dla-2938");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-21716");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/twisted");
  script_set_attribute(attribute:"solution", value:
"Upgrade the twisted packages.

For Debian 9 Stretch, this problem has been fixed in version 16.6.0-2+deb9u2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-21716");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-twisted");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-twisted-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-twisted-bin-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-twisted-conch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-twisted-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-twisted-mail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-twisted-names");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-twisted-news");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-twisted-runner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-twisted-runner-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-twisted-web");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-twisted-words");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-twisted");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-twisted-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-twisted-bin-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:twisted-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('audit.inc');
include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var release = get_kb_item('Host/Debian/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Debian');
var release = chomp(release);
if (! preg(pattern:"^(9)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 9.0', 'Debian ' + release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '9.0', 'prefix': 'python-twisted', 'reference': '16.6.0-2+deb9u2'},
    {'release': '9.0', 'prefix': 'python-twisted-bin', 'reference': '16.6.0-2+deb9u2'},
    {'release': '9.0', 'prefix': 'python-twisted-bin-dbg', 'reference': '16.6.0-2+deb9u2'},
    {'release': '9.0', 'prefix': 'python-twisted-conch', 'reference': '16.6.0-2+deb9u2'},
    {'release': '9.0', 'prefix': 'python-twisted-core', 'reference': '16.6.0-2+deb9u2'},
    {'release': '9.0', 'prefix': 'python-twisted-mail', 'reference': '16.6.0-2+deb9u2'},
    {'release': '9.0', 'prefix': 'python-twisted-names', 'reference': '16.6.0-2+deb9u2'},
    {'release': '9.0', 'prefix': 'python-twisted-news', 'reference': '16.6.0-2+deb9u2'},
    {'release': '9.0', 'prefix': 'python-twisted-runner', 'reference': '16.6.0-2+deb9u2'},
    {'release': '9.0', 'prefix': 'python-twisted-runner-dbg', 'reference': '16.6.0-2+deb9u2'},
    {'release': '9.0', 'prefix': 'python-twisted-web', 'reference': '16.6.0-2+deb9u2'},
    {'release': '9.0', 'prefix': 'python-twisted-words', 'reference': '16.6.0-2+deb9u2'},
    {'release': '9.0', 'prefix': 'python3-twisted', 'reference': '16.6.0-2+deb9u2'},
    {'release': '9.0', 'prefix': 'python3-twisted-bin', 'reference': '16.6.0-2+deb9u2'},
    {'release': '9.0', 'prefix': 'python3-twisted-bin-dbg', 'reference': '16.6.0-2+deb9u2'},
    {'release': '9.0', 'prefix': 'twisted-doc', 'reference': '16.6.0-2+deb9u2'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var release = NULL;
  var prefix = NULL;
  var reference = NULL;
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['prefix'])) prefix = package_array['prefix'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (release && prefix && reference) {
    if (deb_check(release:release, prefix:prefix, reference:reference)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'python-twisted / python-twisted-bin / python-twisted-bin-dbg / etc');
}
