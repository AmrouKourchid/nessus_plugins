#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3037. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(161725);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/24");

  script_cve_id("CVE-2019-2201");

  script_name(english:"Debian DLA-3037-1 : libjpeg-turbo - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 9 host has packages installed that are affected by a vulnerability as referenced in the dla-3037
advisory.

    Several integer overflows have been discovered in TurboJPEG, a JPEG image library, which can lead to a
    denial of service (application crash) if someone attempts to compress or decompress gigapixel images with
    the TurboJPEG API. For Debian 9 stretch, this problem has been fixed in version 1:1.5.1-2+deb9u2. We
    recommend that you upgrade your libjpeg-turbo packages. For the detailed security status of libjpeg-turbo
    please refer to its security tracker page at: https://security-tracker.debian.org/tracker/libjpeg-turbo
    Further information about Debian LTS security advisories, how to apply these updates to your system and
    frequently asked questions can be found at: https://wiki.debian.org/LTS

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://security-tracker.debian.org/tracker/source-package/libjpeg-turbo
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9774e827");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2022/dla-3037");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-2201");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/libjpeg-turbo");
  script_set_attribute(attribute:"solution", value:
"Upgrade the libjpeg-turbo packages.

For Debian 9 stretch, this problem has been fixed in version 1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-2201");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libjpeg-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libjpeg-turbo-progs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libjpeg62-turbo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libjpeg62-turbo-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libturbojpeg0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libturbojpeg0-dev");
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
    {'release': '9.0', 'prefix': 'libjpeg-dev', 'reference': '1:1.5.1-2+deb9u2'},
    {'release': '9.0', 'prefix': 'libjpeg-turbo-progs', 'reference': '1:1.5.1-2+deb9u2'},
    {'release': '9.0', 'prefix': 'libjpeg62-turbo', 'reference': '1:1.5.1-2+deb9u2'},
    {'release': '9.0', 'prefix': 'libjpeg62-turbo-dev', 'reference': '1:1.5.1-2+deb9u2'},
    {'release': '9.0', 'prefix': 'libturbojpeg0', 'reference': '1:1.5.1-2+deb9u2'},
    {'release': '9.0', 'prefix': 'libturbojpeg0-dev', 'reference': '1:1.5.1-2+deb9u2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libjpeg-dev / libjpeg-turbo-progs / libjpeg62-turbo / etc');
}
