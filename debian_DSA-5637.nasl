#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5637. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(191759);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/24");

  script_cve_id(
    "CVE-2023-46724",
    "CVE-2023-46728",
    "CVE-2023-46846",
    "CVE-2023-46847",
    "CVE-2023-46848",
    "CVE-2023-49285",
    "CVE-2023-49286",
    "CVE-2023-50269",
    "CVE-2024-23638",
    "CVE-2024-25111",
    "CVE-2024-25617"
  );

  script_name(english:"Debian dsa-5637 : squid - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 / 12 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5637 advisory.

    -----BEGIN PGP SIGNED MESSAGE-----
    Hash: SHA512

    - -------------------------------------------------------------------------
    Debian Security Advisory DSA-5637-1                   security@debian.org
    https://www.debian.org/security/                          Markus Koschany
    March 08, 2024                        https://www.debian.org/security/faq
    - -------------------------------------------------------------------------

    Package        : squid
    CVE ID         : CVE-2023-46724 CVE-2023-46846 CVE-2023-46847 CVE-2023-49285
                     CVE-2023-49286 CVE-2023-50269 CVE-2024-23638 CVE-2024-25617
                     CVE-2023-46848 CVE-2024-25111
    Debian Bug     : 1055252 1054537 1055250 1055251 1058721

    Several security vulnerabilities have been discovered in Squid, a full featured
    web proxy cache. Due to programming errors in Squid's HTTP request parsing,
    remote attackers may be able to execute a denial of service attack by sending
    large X-Forwarded-For header or trigger a stack buffer overflow while
    performing HTTP Digest authentication. Other issues facilitate request
    smuggling past a firewall or a denial of service against Squid's Helper process
    management.

    In regard to CVE-2023-46728: Please note that support for the Gopher protocol
    has simply been removed in future Squid versions. There are no plans by the
    upstream developers of Squid to fix this issue. We recommend to reject all
    Gopher URL requests instead.

    For the oldstable distribution (bullseye), these problems have been fixed
    in version 4.13-10+deb11u3.

    For the stable distribution (bookworm), these problems have been fixed in
    version 5.7-2+deb12u1.

    We recommend that you upgrade your squid packages.

    For the detailed security status of squid please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/squid

    Further information about Debian Security Advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://www.debian.org/security/

    Mailing list: debian-security-announce@lists.debian.org
    -----BEGIN PGP SIGNATURE-----

    iQKTBAEBCgB9FiEErPPQiO8y7e9qGoNf2a0UuVE7UeQFAmXrHBNfFIAAAAAALgAo
    aXNzdWVyLWZwckBub3RhdGlvbnMub3BlbnBncC5maWZ0aGhvcnNlbWFuLm5ldEFD
    RjNEMDg4RUYzMkVERUY2QTFBODM1RkQ5QUQxNEI5NTEzQjUxRTQACgkQ2a0UuVE7
    UeSFng/+JAY5jG6Z/fVFf2M9SsqFhQm8mGT1CgOx39dYirUkdpcFOyADqWopwv+q
    tci90QFuhnreW1DmO1GYRlZro+37iRjiryRKxETpUB1AnpPWs6RnyAA+mrqssDqg
    PxxFkqpJFtpMhZU3VkDDbTkkvK2T0Hwjdn8TND6qA+B56exwW2DEZlm5aqCPiWRf
    pdzPZTOZJEV2fT4UPWduiIN1l94VsLktfZY5Ox0/HmrdkAWJJFXQhj3wZPcbFLbB
    leQ7Nkq6mpuw98UxOSa7hsE0crPm6ctrf7AYMx+qojtWJFcbFE+mUqzcf0aFYp0L
    EfTSVAOVEXvbFytlX/oSWYE5GrZtTrnwProiXFJT7WvDYN2Mbqxgp/jB3jZygmrZ
    rknvF84haHX16ZMXRlBDOlx1E3XSCB+/xRynwbGQe8RPzSRlOKuiFqn+qr3qCtOd
    5Ua2+ZJXDpEP4aUseFb94FwJRfs9onBS+EYPt2xwcxcBGUiMJ/lY9Fj9p5MjQ1bZ
    nCXuRNo2ao6qumLSraK2qPle7AucbuOtiMDsMFi6rGu3H0RVlk7oWGFO4rMRAcvX
    IBYU2bWBIyi7J4IvJd+07QfNgofPvcld9XN7/LDgizmMZpCorpPq39Ta24y7U3e5
    Zv+ye/kOYKuD0ij7M7jkT2hgxq6kKdlSEZbZ/wrlkSILrcjgwqw=
    =qmZY
    -----END PGP SIGNATURE-----



Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/squid");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-46724");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-46728");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-46846");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-46847");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-46848");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-49285");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-49286");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-50269");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-23638");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-25111");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-25617");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bookworm/squid");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/squid");
  script_set_attribute(attribute:"solution", value:
"Upgrade the squid packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-46846");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/03/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squid-cgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squid-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squid-openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squid-purge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squidclient");
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
    {'release': '11.0', 'prefix': 'squid', 'reference': '4.13-10+deb11u3'},
    {'release': '11.0', 'prefix': 'squid-cgi', 'reference': '4.13-10+deb11u3'},
    {'release': '11.0', 'prefix': 'squid-common', 'reference': '4.13-10+deb11u3'},
    {'release': '11.0', 'prefix': 'squid-openssl', 'reference': '4.13-10+deb11u3'},
    {'release': '11.0', 'prefix': 'squid-purge', 'reference': '4.13-10+deb11u3'},
    {'release': '11.0', 'prefix': 'squidclient', 'reference': '4.13-10+deb11u3'},
    {'release': '12.0', 'prefix': 'squid', 'reference': '5.7-2+deb12u1'},
    {'release': '12.0', 'prefix': 'squid-cgi', 'reference': '5.7-2+deb12u1'},
    {'release': '12.0', 'prefix': 'squid-common', 'reference': '5.7-2+deb12u1'},
    {'release': '12.0', 'prefix': 'squid-openssl', 'reference': '5.7-2+deb12u1'},
    {'release': '12.0', 'prefix': 'squid-purge', 'reference': '5.7-2+deb12u1'},
    {'release': '12.0', 'prefix': 'squidclient', 'reference': '5.7-2+deb12u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'squid / squid-cgi / squid-common / squid-openssl / squid-purge / etc');
}
