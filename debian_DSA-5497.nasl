#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5497. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(181446);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/27");

  script_cve_id("CVE-2023-4863");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/10/04");

  script_name(english:"Debian DSA-5497-1 : libwebp - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 12 host has packages installed that are affected by a vulnerability as referenced in the dsa-5497
advisory.

    A buffer overflow in parsing WebP images may result in the execution of arbitrary code. For the stable
    distribution (bookworm), this problem has been fixed in version 1.2.4-0.2+deb12u1. We recommend that you
    upgrade your libwebp packages. For the detailed security status of libwebp please refer to its security
    tracker page at: https://security-tracker.debian.org/tracker/libwebp

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/libwebp");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2023/dsa-5497");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-4863");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bookworm/libwebp");
  script_set_attribute(attribute:"solution", value:
"Upgrade the libwebp packages.

For the stable distribution (bookworm), this problem has been fixed in version 1.2.4-0.2+deb12u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-4863");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/07/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/09/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwebp-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwebp7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwebpdemux2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwebpmux3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:webp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:12.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'release': '12.0', 'prefix': 'libwebp-dev', 'reference': '1.2.4-0.2+deb12u1'},
    {'release': '12.0', 'prefix': 'libwebp7', 'reference': '1.2.4-0.2+deb12u1'},
    {'release': '12.0', 'prefix': 'libwebpdemux2', 'reference': '1.2.4-0.2+deb12u1'},
    {'release': '12.0', 'prefix': 'libwebpmux3', 'reference': '1.2.4-0.2+deb12u1'},
    {'release': '12.0', 'prefix': 'webp', 'reference': '1.2.4-0.2+deb12u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libwebp-dev / libwebp7 / libwebpdemux2 / libwebpmux3 / webp');
}
