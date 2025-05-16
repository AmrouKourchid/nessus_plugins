#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3941. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(209907);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/30");

  script_cve_id("CVE-2023-32668", "CVE-2024-25262");

  script_name(english:"Debian dla-3941 : libkpathsea-dev - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3941 advisory.

    - -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3941-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                   Bastien Roucaris
    October 29, 2024                              https://wiki.debian.org/LTS
    - -------------------------------------------------------------------------

    Package        : texlive-bin
    Version        : 2020.20200327.54578-7+deb11u2
    CVE ID         : CVE-2023-32668 CVE-2024-25262
    Debian Bug     : 1036470 1064517

    texlive, a popular software distribution for the TeX typesetting system
    that includes major TeX-related programs, macro packages, and fonts,
    was affected by two vulnerabilties.

    CVE-2023-32668

        A document (compiled with the default settings)
        was allowed to make arbitrary network requests.
        This occurs because full access to the socket library was
        permitted by default, as stated in the documentation.

    CVE-2024-25262

        A heap buffer overflow was found via
        the function ttfLoadHDMX:ttfdump. This vulnerability
        allows attackers to cause a Denial of Service (DoS)
        via supplying a crafted TTF file.

    For Debian 11 bullseye, these problems have been fixed in version
    2020.20200327.54578-7+deb11u2.

    We recommend that you upgrade your texlive-bin packages.

    For the detailed security status of texlive-bin please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/texlive-bin

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/texlive-bin");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-32668");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-25262");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/texlive-bin");
  script_set_attribute(attribute:"solution", value:
"Upgrade the libkpathsea-dev packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-32668");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkpathsea-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkpathsea6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libptexenc-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libptexenc1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsynctex-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsynctex2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtexlua53");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtexlua53-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtexluajit-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtexluajit2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:texlive-binaries");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(11)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 11.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '11.0', 'prefix': 'libkpathsea-dev', 'reference': '2020.20200327.54578-7+deb11u2'},
    {'release': '11.0', 'prefix': 'libkpathsea6', 'reference': '2020.20200327.54578-7+deb11u2'},
    {'release': '11.0', 'prefix': 'libptexenc-dev', 'reference': '2020.20200327.54578-7+deb11u2'},
    {'release': '11.0', 'prefix': 'libptexenc1', 'reference': '2020.20200327.54578-7+deb11u2'},
    {'release': '11.0', 'prefix': 'libsynctex-dev', 'reference': '2020.20200327.54578-7+deb11u2'},
    {'release': '11.0', 'prefix': 'libsynctex2', 'reference': '2020.20200327.54578-7+deb11u2'},
    {'release': '11.0', 'prefix': 'libtexlua53', 'reference': '2020.20200327.54578-7+deb11u2'},
    {'release': '11.0', 'prefix': 'libtexlua53-dev', 'reference': '2020.20200327.54578-7+deb11u2'},
    {'release': '11.0', 'prefix': 'libtexluajit-dev', 'reference': '2020.20200327.54578-7+deb11u2'},
    {'release': '11.0', 'prefix': 'libtexluajit2', 'reference': '2020.20200327.54578-7+deb11u2'},
    {'release': '11.0', 'prefix': 'texlive-binaries', 'reference': '2020.20200327.54578-7+deb11u2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libkpathsea-dev / libkpathsea6 / libptexenc-dev / libptexenc1 / etc');
}
