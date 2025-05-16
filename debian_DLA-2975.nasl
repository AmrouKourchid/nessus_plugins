#%NASL_MIN_LEVEL 70300
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-2975. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159625);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/24");

  script_cve_id(
    "CVE-2020-27842",
    "CVE-2020-27843",
    "CVE-2021-29338",
    "CVE-2022-1122"
  );
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Debian DLA-2975-1 : openjpeg2 - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-2975 advisory.

    Multiple vulnerabilities have been discovered in openjpeg2, the open-source JPEG 2000 codec.
    CVE-2020-27842 Null pointer dereference through specially crafted input. The highest impact of this flaw
    is to application availability. CVE-2020-27843 The flaw allows an attacker to provide specially crafted
    input to the conversion or encoding functionality, causing an out-of-bounds read. The highest threat from
    this vulnerability is system availability. CVE-2021-29338 Integer overflow allows remote attackers to
    crash the application, causing a denial of service. This occurs when the attacker uses the command line
    option -ImgDir on a directory that contains 1048576 files. CVE-2022-1122 Input directory with a large
    number of files can lead to a segmentation fault and a denial of service due to a call of free() on an
    uninitialized pointer. For Debian 9 stretch, these problems have been fixed in version 2.1.2-1.1+deb9u7.
    We recommend that you upgrade your openjpeg2 packages. For the detailed security status of openjpeg2
    please refer to its security tracker page at: https://security-tracker.debian.org/tracker/openjpeg2
    Further information about Debian LTS security advisories, how to apply these updates to your system and
    frequently asked questions can be found at: https://wiki.debian.org/LTS

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/openjpeg2");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2022/dla-2975");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-27842");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-27843");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-29338");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1122");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/openjpeg2");
  script_set_attribute(attribute:"solution", value:
"Upgrade the openjpeg2 packages.

For Debian 9 stretch, these problems have been fixed in version 2.1.2-1.1+deb9u7.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-27843");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-1122");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopenjp2-7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopenjp2-7-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopenjp2-7-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopenjp2-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopenjp3d-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopenjp3d7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopenjpip-dec-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopenjpip-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopenjpip-viewer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopenjpip7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'release': '9.0', 'prefix': 'libopenjp2-7', 'reference': '2.1.2-1.1+deb9u7'},
    {'release': '9.0', 'prefix': 'libopenjp2-7-dbg', 'reference': '2.1.2-1.1+deb9u7'},
    {'release': '9.0', 'prefix': 'libopenjp2-7-dev', 'reference': '2.1.2-1.1+deb9u7'},
    {'release': '9.0', 'prefix': 'libopenjp2-tools', 'reference': '2.1.2-1.1+deb9u7'},
    {'release': '9.0', 'prefix': 'libopenjp3d-tools', 'reference': '2.1.2-1.1+deb9u7'},
    {'release': '9.0', 'prefix': 'libopenjp3d7', 'reference': '2.1.2-1.1+deb9u7'},
    {'release': '9.0', 'prefix': 'libopenjpip-dec-server', 'reference': '2.1.2-1.1+deb9u7'},
    {'release': '9.0', 'prefix': 'libopenjpip-server', 'reference': '2.1.2-1.1+deb9u7'},
    {'release': '9.0', 'prefix': 'libopenjpip-viewer', 'reference': '2.1.2-1.1+deb9u7'},
    {'release': '9.0', 'prefix': 'libopenjpip7', 'reference': '2.1.2-1.1+deb9u7'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libopenjp2-7 / libopenjp2-7-dbg / libopenjp2-7-dev / libopenjp2-tools / etc');
}
