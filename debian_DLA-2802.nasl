#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-2802. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154749);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/24");

  script_cve_id(
    "CVE-2018-16062",
    "CVE-2018-16402",
    "CVE-2018-18310",
    "CVE-2018-18520",
    "CVE-2018-18521",
    "CVE-2019-7150",
    "CVE-2019-7665"
  );

  script_name(english:"Debian DLA-2802-1 : elfutils - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-2802 advisory.

    Several vulnerabilities were fixed in elfutils, a collection of utilities and libraries to handle ELF
    objects. CVE-2018-16062 dwarf_getaranges in dwarf_getaranges.c in libdw allowed a denial of service (heap-
    based buffer over-read) via a crafted file. CVE-2018-16402 libelf/elf_end.c in allowed to cause a denial
    of service (double free and application crash) because it tried to decompress twice. CVE-2018-18310 An
    invalid memory address dereference libdwfl allowed a denial of service (application crash) via a crafted
    file. CVE-2018-18520 A use-after-free in recursive ELF ar files allowed a denial of service (application
    crash) via a crafted file. CVE-2018-18521 A divide-by-zero in arlib_add_symbols() allowed a denial of
    service (application crash) via a crafted file. CVE-2019-7150 A segmentation fault could occur due to
    dwfl_segment_report_module() not checking whether the dyn data read from a core file is truncated.
    CVE-2019-7665 NT_PLATFORM core notes contain a zero terminated string allowed a denial of service
    (application crash) via a crafted file. For Debian 9 stretch, these problems have been fixed in version
    0.168-1+deb9u1. We recommend that you upgrade your elfutils packages. For the detailed security status of
    elfutils please refer to its security tracker page at: https://security-
    tracker.debian.org/tracker/elfutils Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be found at: https://wiki.debian.org/LTS

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=907562");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/elfutils");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2021/dla-2802");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-16062");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-16402");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-18310");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-18520");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-18521");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-7150");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-7665");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/elfutils");
  script_set_attribute(attribute:"solution", value:
"Upgrade the elfutils packages.

For Debian 9 stretch, these problems have been fixed in version 0.168-1+deb9u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-16402");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:elfutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libasm-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libasm1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libdw-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libdw1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libelf-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libelf1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'release': '9.0', 'prefix': 'elfutils', 'reference': '0.168-1+deb9u1'},
    {'release': '9.0', 'prefix': 'libasm-dev', 'reference': '0.168-1+deb9u1'},
    {'release': '9.0', 'prefix': 'libasm1', 'reference': '0.168-1+deb9u1'},
    {'release': '9.0', 'prefix': 'libdw-dev', 'reference': '0.168-1+deb9u1'},
    {'release': '9.0', 'prefix': 'libdw1', 'reference': '0.168-1+deb9u1'},
    {'release': '9.0', 'prefix': 'libelf-dev', 'reference': '0.168-1+deb9u1'},
    {'release': '9.0', 'prefix': 'libelf1', 'reference': '0.168-1+deb9u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'elfutils / libasm-dev / libasm1 / libdw-dev / libdw1 / libelf-dev / etc');
}
