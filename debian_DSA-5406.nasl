#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5406. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(176150);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/08/02");

  script_cve_id("CVE-2023-32700");

  script_name(english:"Debian DSA-5406-1 : texlive-bin - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by a vulnerability as referenced in the dsa-5406
advisory.

  - LuaTeX before 1.17.0 allows execution of arbitrary shell commands when compiling a TeX file obtained from
    an untrusted source. This occurs because luatex-core.lua lets the original io.popen be accessed. This also
    affects TeX Live before 2023 r66984 and MiKTeX before 23.5. (CVE-2023-32700)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/texlive-bin");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2023/dsa-5406");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-32700");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/texlive-bin");
  script_set_attribute(attribute:"solution", value:
"Upgrade the texlive-bin packages.

For the stable distribution (bullseye), this problem has been fixed in version 2020.20200327.54578-7+deb11u1.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-32700");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/20");

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

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'release': '11.0', 'prefix': 'libkpathsea-dev', 'reference': '2020.20200327.54578-7+deb11u1'},
    {'release': '11.0', 'prefix': 'libkpathsea6', 'reference': '2020.20200327.54578-7+deb11u1'},
    {'release': '11.0', 'prefix': 'libptexenc-dev', 'reference': '2020.20200327.54578-7+deb11u1'},
    {'release': '11.0', 'prefix': 'libptexenc1', 'reference': '2020.20200327.54578-7+deb11u1'},
    {'release': '11.0', 'prefix': 'libsynctex-dev', 'reference': '2020.20200327.54578-7+deb11u1'},
    {'release': '11.0', 'prefix': 'libsynctex2', 'reference': '2020.20200327.54578-7+deb11u1'},
    {'release': '11.0', 'prefix': 'libtexlua53', 'reference': '2020.20200327.54578-7+deb11u1'},
    {'release': '11.0', 'prefix': 'libtexlua53-dev', 'reference': '2020.20200327.54578-7+deb11u1'},
    {'release': '11.0', 'prefix': 'libtexluajit-dev', 'reference': '2020.20200327.54578-7+deb11u1'},
    {'release': '11.0', 'prefix': 'libtexluajit2', 'reference': '2020.20200327.54578-7+deb11u1'},
    {'release': '11.0', 'prefix': 'texlive-binaries', 'reference': '2020.20200327.54578-7+deb11u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libkpathsea-dev / libkpathsea6 / libptexenc-dev / libptexenc1 / etc');
}
