#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5639. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(192041);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/24");

  script_cve_id("CVE-2024-2400");
  script_xref(name:"IAVA", value:"2024-A-0167-S");

  script_name(english:"Debian dsa-5639 : chromium - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 12 host has packages installed that are affected by a vulnerability as referenced in the dsa-5639
advisory.

    -----BEGIN PGP SIGNED MESSAGE-----
    Hash: SHA256

    - -------------------------------------------------------------------------
    Debian Security Advisory DSA-5639-1                   security@debian.org
    https://www.debian.org/security/                           Andres Salomon
    March 13, 2024                        https://www.debian.org/security/faq
    - -------------------------------------------------------------------------

    Package        : chromium
    CVE ID         : CVE-2024-2400

    Security issues were discovered in Chromium, which could result
    in the execution of arbitrary code, denial of service or information
    disclosure.

    For the stable distribution (bookworm), this problem has been fixed in
    version 122.0.6261.128-1~deb12u1.

    We recommend that you upgrade your chromium packages.

    For the detailed security status of chromium please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/chromium

    Further information about Debian Security Advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://www.debian.org/security/

    Mailing list: debian-security-announce@lists.debian.org
    -----BEGIN PGP SIGNATURE-----

    iQIzBAEBCAAdFiEEUAUk+X1YiTIjs19qZF0CR8NudjcFAmXx7LIACgkQZF0CR8Nu
    djcWZA/9E8Fv7qz1xdAfgt/f8Iueu24Ct3n2/0yIvZ7GZCEHhyeU7jPaieh3LKL2
    HIvafH9UWOlU643jHefoX4xQVos3uc8VuXjBAfX0AJrRl0N0JR4am7EpbKJ/WkQj
    Sqpklh9QFbm+0g5iKbhWVA3KI+IZ8wkx/g4QUxYpmF2Pou6xZWIr3RkWX0T2x/Bb
    4nG9CrVOwQg5BltP6jPln269sU/5Olr6VL3S4KN+1CdBySmXrrhKVsxpbi7qLa9d
    +czGAjYhAp/2YGCEz67Ib55n/1mhaCL7fqU2cZHBdwqYjTBJqOnsGVJSm8Q7hbJ2
    i7SaETJkk9oVYIN8XUw2xzdONGS44Xd/rhUesJzsfduYNSD+Yhq+AhqKmxGILshM
    C+Vz6elNGgG7mKaUwj7/6FtN6VmP0jiVbHMLRpH1ROvph2uENUQYPE/slfkYluNh
    PTU4BefBnGghyfj6E9HBV3AjWTR/EmsrMUF9+kbs6AEwVlAiVArJorQ63kbRQ5KX
    FdvJnQ22XDztR+zWwfS5QhQAyEmpdhO/UoFfVyhWnzbfolEUkEmv/MlTFndCoiYW
    ErmqpXLui7Iq66rEgjLJHv2V8s6jJvsT6a75XdjRCaZkCKab/f/pCI6xLZtn2JhL
    6LkGeY2qpmZOsEwieBbVvsix6ysmmmXIinEmE7Ckf66ENs7TKZw=
    =RmDM
    -----END PGP SIGNATURE-----



Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/chromium");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-2400");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bookworm/chromium");
  script_set_attribute(attribute:"solution", value:
"Upgrade the chromium packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-2400");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/03/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium-driver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium-l10n");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium-sandbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium-shell");
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
if (! preg(pattern:"^(12)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 12.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '12.0', 'prefix': 'chromium', 'reference': '122.0.6261.128-1~deb12u1'},
    {'release': '12.0', 'prefix': 'chromium-common', 'reference': '122.0.6261.128-1~deb12u1'},
    {'release': '12.0', 'prefix': 'chromium-driver', 'reference': '122.0.6261.128-1~deb12u1'},
    {'release': '12.0', 'prefix': 'chromium-l10n', 'reference': '122.0.6261.128-1~deb12u1'},
    {'release': '12.0', 'prefix': 'chromium-sandbox', 'reference': '122.0.6261.128-1~deb12u1'},
    {'release': '12.0', 'prefix': 'chromium-shell', 'reference': '122.0.6261.128-1~deb12u1'}
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
