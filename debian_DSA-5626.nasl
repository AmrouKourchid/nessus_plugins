#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5626. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(190676);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/24");

  script_cve_id("CVE-2023-50387", "CVE-2023-50868");

  script_name(english:"Debian dsa-5626 : pdns-recursor - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 12 host has a package installed that is affected by multiple vulnerabilities as referenced in the
dsa-5626 advisory.

    -----BEGIN PGP SIGNED MESSAGE-----
    Hash: SHA512

    - -------------------------------------------------------------------------
    Debian Security Advisory DSA-5626-1                   security@debian.org
    https://www.debian.org/security/                       Moritz Muehlenhoff
    February 18, 2024                     https://www.debian.org/security/faq
    - -------------------------------------------------------------------------

    Package        : pdns-recursor
    CVE ID         : CVE-2023-50387 CVE-2023-50868

    It was discovered that malformed DNSSEC records within a DNS zone could
    result in denial of service against PDNS Recursor, a resolving
    name server.

    For the stable distribution (bookworm), these problems have been fixed in
    version 4.8.6-1.

    We recommend that you upgrade your pdns-recursor packages.

    For the detailed security status of pdns-recursor please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/pdns-recursor

    Further information about Debian Security Advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://www.debian.org/security/

    Mailing list: debian-security-announce@lists.debian.org
    -----BEGIN PGP SIGNATURE-----

    iQIzBAEBCgAdFiEEtuYvPRKsOElcDakFEMKTtsN8TjYFAmXSMZcACgkQEMKTtsN8
    TjaCXA//RzokD4ns3XxUhHK3Q3i2KDp1Y1c2sbZzSRXw0Lw7K8xrCqZDksURciCk
    ThiKqF+F3sKHaRt2Agj99DwWJ7fC+BuHJ0s73yRsrKX7HL6At/z1XE+Cw4UU775c
    3pydDoS+hTfLGbSLgnpdKg7do/u9uZ29tMpTWv6QpNl5mF0irsKnbYdz9XEe9SaJ
    nlj5tpBYhptZP4AlmDXbWr4tIjx01X3JWOqKbsT8/08JYqd0AcKlihsqs4Wv1ggB
    mRBo4/1YjPD3ONgqrswikehbd9dMtzyFIJy6Yjo/HxVe1RnQH39rx4PzdkezP9MX
    4Ug6a2vzcqy3E3kGBgetQ6e7FETnV+94XFN2UfUtmBWjiTmU84k3+isgb8Xe+liF
    FVx86OZbUlkQ+tRgsNHw3uSsJf+5J3kr9Bacs4xdvZXxMSz5JrG484/YUd1wHVb3
    S/bv0vC7/BLhletXBhoz3MBa0m7qntNFexJyYoe2AYD1WLTfl10IuiZwpO6lnolj
    2XIIulORIhi72TdC4L7ZE6/fZr3XilMA4Y06ODlAQw3hpwf66YcOjuTC2lgrqoX0
    9zyGrO3j729rW/O5JASnSR5jFv6eXV9a+YEqN7f6vgTjiE0GABpAdQ8CSp95WVLi
    s51UtQ37FZdPp27/2lCFAd4UMnrJmDnVpsPTVFyNjQoBuKYdf8Y=
    =rNYz
    -----END PGP SIGNATURE-----



Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security-tracker.debian.org/tracker/source-package/pdns-recursor
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?51aad11d");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-50387");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-50868");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bookworm/pdns-recursor");
  script_set_attribute(attribute:"solution", value:
"Upgrade the pdns-recursor packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-50387");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pdns-recursor");
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
if (! preg(pattern:"^(12)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 12.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '12.0', 'prefix': 'pdns-recursor', 'reference': '4.8.6-1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'pdns-recursor');
}
