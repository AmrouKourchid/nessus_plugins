#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5603. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(189388);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/24");

  script_cve_id(
    "CVE-2023-6816",
    "CVE-2024-0229",
    "CVE-2024-0408",
    "CVE-2024-0409",
    "CVE-2024-21885",
    "CVE-2024-21886"
  );

  script_name(english:"Debian dsa-5603 : xdmx - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 / 12 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5603 advisory.

    -----BEGIN PGP SIGNED MESSAGE-----
    Hash: SHA512

    - -------------------------------------------------------------------------
    Debian Security Advisory DSA-5603-1                   security@debian.org
    https://www.debian.org/security/                     Salvatore Bonaccorso
    January 23, 2024                      https://www.debian.org/security/faq
    - -------------------------------------------------------------------------

    Package        : xorg-server
    CVE ID         : CVE-2023-6816 CVE-2024-0229 CVE-2024-0408 CVE-2024-0409
                     CVE-2024-21885 CVE-2024-21886

    Several vulnerabilities were discovered in the Xorg X server, which may
    result in privilege escalation if the X server is running privileged
    or denial of service.

    For the oldstable distribution (bullseye), these problems have been fixed
    in version 2:1.20.11-1+deb11u11.

    For the stable distribution (bookworm), these problems have been fixed in
    version 2:21.1.7-3+deb12u5.

    We recommend that you upgrade your xorg-server packages.

    For the detailed security status of xorg-server please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/xorg-server

    Further information about Debian Security Advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://www.debian.org/security/

    Mailing list: debian-security-announce@lists.debian.org
    -----BEGIN PGP SIGNATURE-----

    iQKTBAEBCgB9FiEERkRAmAjBceBVMd3uBUy48xNDz0QFAmWwGD1fFIAAAAAALgAo
    aXNzdWVyLWZwckBub3RhdGlvbnMub3BlbnBncC5maWZ0aGhvcnNlbWFuLm5ldDQ2
    NDQ0MDk4MDhDMTcxRTA1NTMxRERFRTA1NENCOEYzMTM0M0NGNDQACgkQBUy48xND
    z0TTQQ//W4eLUMTFmwz8KX3YIo8OLURD91ID1bIjjvrT5uYckPbMVWcIe07tnrU4
    GM0Ad09Rq6FCLKNbNqVj8tfvHrA+3VYlNcjD01AnqRYk3zZ85CkMf9tKrUT+/1pB
    dcyyponNDY18MxJR/3plDdIhPjoaLv+dtZY8kYXzf8qUtk1Rn1C/DbttLzLRC/5Q
    7K+aDNoBZqyw7xmoZkmvBK8rf4x2ZtpuetCWvEsgRnCE6YVYj/mCfoiDkIOhM7jw
    jSv3QpaQ8BzrozbhbB6BgIHSBRTWfgjNcUOqj8I2tPpSTIuDdlTQ+BbA7OKz2+k/
    SniFezxPLPFovg3vchOYjxLlKXEl54bhm5y/qFUCMoEPEzLhY6w/8UXo1ggWgtBs
    7N6vHNqlS67fOZKiLXhrIsoaAoggF+PvRX2zroa6FH9i4nhl4WRxyHxX/JCLX9yU
    28gfwLMPuHqklCCNTwWOlFs/1zMJB8SF563/70CZilBMfFSy0rz80id8Wgv5zpcQ
    fkW10T9cg8lMF9w5sN1wmb0Tww9dWCehOXLMFa9ATEm/jR6yqWSyjL/0BZ2izeow
    WwLKeZhk+s5iv+IFRjXqkoWlKpljhOTodKhYVYlyrUK3m66hhIYU8XDtzNGRB+i6
    M/PO/raW3dpB7WPChELMQiYo9kqFLno8E7mC5sjvCIq425kw9Rw=
    =dehR
    -----END PGP SIGNATURE-----



Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/xorg-server");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-6816");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-0229");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-0408");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-0409");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-21885");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-21886");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bookworm/xorg-server");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/xorg-server");
  script_set_attribute(attribute:"solution", value:
"Upgrade the xdmx packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-6816");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/01/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xdmx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xdmx-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xnest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xorg-server-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xserver-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xserver-xephyr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xserver-xorg-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xserver-xorg-core-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xserver-xorg-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xserver-xorg-legacy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xvfb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xwayland");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:12.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(11)\.[0-9]+|^(12)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 11.0 / 12.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '11.0', 'prefix': 'xdmx', 'reference': '2:1.20.11-1+deb11u11'},
    {'release': '11.0', 'prefix': 'xdmx-tools', 'reference': '2:1.20.11-1+deb11u11'},
    {'release': '11.0', 'prefix': 'xnest', 'reference': '2:1.20.11-1+deb11u11'},
    {'release': '11.0', 'prefix': 'xorg-server-source', 'reference': '2:1.20.11-1+deb11u11'},
    {'release': '11.0', 'prefix': 'xserver-common', 'reference': '2:1.20.11-1+deb11u11'},
    {'release': '11.0', 'prefix': 'xserver-xephyr', 'reference': '2:1.20.11-1+deb11u11'},
    {'release': '11.0', 'prefix': 'xserver-xorg-core', 'reference': '2:1.20.11-1+deb11u11'},
    {'release': '11.0', 'prefix': 'xserver-xorg-core-udeb', 'reference': '2:1.20.11-1+deb11u11'},
    {'release': '11.0', 'prefix': 'xserver-xorg-dev', 'reference': '2:1.20.11-1+deb11u11'},
    {'release': '11.0', 'prefix': 'xserver-xorg-legacy', 'reference': '2:1.20.11-1+deb11u11'},
    {'release': '11.0', 'prefix': 'xvfb', 'reference': '2:1.20.11-1+deb11u11'},
    {'release': '11.0', 'prefix': 'xwayland', 'reference': '2:1.20.11-1+deb11u11'},
    {'release': '12.0', 'prefix': 'xnest', 'reference': '2:21.1.7-3+deb12u5'},
    {'release': '12.0', 'prefix': 'xorg-server-source', 'reference': '2:21.1.7-3+deb12u5'},
    {'release': '12.0', 'prefix': 'xserver-common', 'reference': '2:21.1.7-3+deb12u5'},
    {'release': '12.0', 'prefix': 'xserver-xephyr', 'reference': '2:21.1.7-3+deb12u5'},
    {'release': '12.0', 'prefix': 'xserver-xorg-core', 'reference': '2:21.1.7-3+deb12u5'},
    {'release': '12.0', 'prefix': 'xserver-xorg-core-udeb', 'reference': '2:21.1.7-3+deb12u5'},
    {'release': '12.0', 'prefix': 'xserver-xorg-dev', 'reference': '2:21.1.7-3+deb12u5'},
    {'release': '12.0', 'prefix': 'xserver-xorg-legacy', 'reference': '2:21.1.7-3+deb12u5'},
    {'release': '12.0', 'prefix': 'xvfb', 'reference': '2:21.1.7-3+deb12u5'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'xdmx / xdmx-tools / xnest / xorg-server-source / xserver-common / etc');
}
