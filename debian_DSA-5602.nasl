#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5602. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(189144);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/24");

  script_cve_id("CVE-2024-0517", "CVE-2024-0518", "CVE-2024-0519");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/02/07");
  script_xref(name:"IAVA", value:"2024-A-0042-S");

  script_name(english:"Debian dsa-5602 : chromium - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 / 12 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5602 advisory.

    -----BEGIN PGP SIGNED MESSAGE-----
    Hash: SHA256

    - -------------------------------------------------------------------------
    Debian Security Advisory DSA-5602-1                   security@debian.org
    https://www.debian.org/security/                           Andres Salomon
    January 17, 2024                      https://www.debian.org/security/faq
    - -------------------------------------------------------------------------

    Package        : chromium
    CVE ID         : CVE-2024-0517 CVE-2024-0518 CVE-2024-0519

    Multiple security issues were discovered in Chromium, which could result
    in the execution of arbitrary code, denial of service or information
    disclosure. An exploit for CVE-2024-0519 exists in the wild.

    For the oldstable distribution (bullseye), these problems have been fixed
    in version 120.0.6099.224-1~deb11u1.

    For the stable distribution (bookworm), these problems have been fixed in
    version 120.0.6099.224-1~deb12u1.

    We recommend that you upgrade your chromium packages.

    For the detailed security status of chromium please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/chromium

    Further information about Debian Security Advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://www.debian.org/security/

    Mailing list: debian-security-announce@lists.debian.org
    -----BEGIN PGP SIGNATURE-----

    iQIzBAEBCAAdFiEEUAUk+X1YiTIjs19qZF0CR8NudjcFAmWoZJcACgkQZF0CR8Nu
    djf/yhAAnSViUZwkqVXDm/yLl3oUfDsOkSooBuPIPexPRiHlcPWY+F4IlBEXgdru
    wN8/EuE4SLTxGxrortr8chuzyHHj2quJI/rOZwA/IBEAJ+X0iC71xyPkeqmS7rhN
    C9iJkwUrTcn+Sx4STBAvo/+7ZKQz9xwgS7Rx1vrmufG+SeCPX5SYvxaj4G/9rUug
    utcMzuQ96/ltfO02h53B9Zc85V0i0h0w7Y+Urmc+PAFnjx7eEToTxU7NhdU3xPVq
    u4a6VHs+TTn0MtcQs79lbq+e25kwQLaCbV4Sa2uOH/kwDFW2KmLNADrHBBgwKt43
    9i5fY6NekPulnVowS0+feLwLAncr9xmA4sd2Qafd6Yvh1RRtwam06Bpmx6wtK3+L
    rX0zQW52BxGC+tRTWzs5lVDFRhNgi8DOPS83+co6NR2Qj87MUD1EU/VsgIphYu/o
    x4DwmgcQMD9NXmrnwOwKDFJk5qx4NBvP1zwGXWpuNxdTCF12IVIMExDZ0MmBRmYA
    bFZedNElzIyNTlTHHcYIA9X5KwC/2pROcTUeDRvRExe9Ej2O5SVn+ltu0EPEIsIm
    C2yuLqrDcmfcuDYd83G0/2xV/NdCxbrxwcT2CoUDqCVdZaXkWGZYrebcH2Ym096d
    /sgZncfqsywdJJQxrBjof7ncooi6ngvnHhKhZNgFBw5732EupLM=
    =u141
    -----END PGP SIGNATURE-----



Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/chromium");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-0517");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-0518");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-0519");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bookworm/chromium");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/chromium");
  script_set_attribute(attribute:"solution", value:
"Upgrade the chromium packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-0519");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium-driver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium-l10n");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium-sandbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium-shell");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:12.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
    {'release': '11.0', 'prefix': 'chromium', 'reference': '120.0.6099.224-1~deb11u1'},
    {'release': '11.0', 'prefix': 'chromium-common', 'reference': '120.0.6099.224-1~deb11u1'},
    {'release': '11.0', 'prefix': 'chromium-driver', 'reference': '120.0.6099.224-1~deb11u1'},
    {'release': '11.0', 'prefix': 'chromium-l10n', 'reference': '120.0.6099.224-1~deb11u1'},
    {'release': '11.0', 'prefix': 'chromium-sandbox', 'reference': '120.0.6099.224-1~deb11u1'},
    {'release': '11.0', 'prefix': 'chromium-shell', 'reference': '120.0.6099.224-1~deb11u1'},
    {'release': '12.0', 'prefix': 'chromium', 'reference': '120.0.6099.224-1~deb12u1'},
    {'release': '12.0', 'prefix': 'chromium-common', 'reference': '120.0.6099.224-1~deb12u1'},
    {'release': '12.0', 'prefix': 'chromium-driver', 'reference': '120.0.6099.224-1~deb12u1'},
    {'release': '12.0', 'prefix': 'chromium-l10n', 'reference': '120.0.6099.224-1~deb12u1'},
    {'release': '12.0', 'prefix': 'chromium-sandbox', 'reference': '120.0.6099.224-1~deb12u1'},
    {'release': '12.0', 'prefix': 'chromium-shell', 'reference': '120.0.6099.224-1~deb12u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'chromium / chromium-common / chromium-driver / chromium-l10n / etc');
}
