#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-2752. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152983);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/01");

  script_cve_id("CVE-2021-40153");

  script_name(english:"Debian DLA-2752-1 : squashfs-tools - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 9 host has packages installed that are affected by a vulnerability as referenced in the dla-2752
advisory.

  - squashfs_opendir in unsquash-1.c in Squashfs-Tools 4.5 stores the filename in the directory entry; this is
    then used by unsquashfs to create the new file during the unsquash. The filename is not validated for
    traversal outside of the destination directory, and thus allows writing to locations outside of the
    destination. (CVE-2021-40153)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://security-tracker.debian.org/tracker/source-package/squashfs-tools
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d374def4");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2021/dla-2752");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-40153");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/squashfs-tools");
  script_set_attribute(attribute:"solution", value:
"Upgrade the squashfs-tools packages.

For Debian 9 stretch, this problem has been fixed in version 1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-40153");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/08/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-tools-dbg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('audit.inc');
include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var release = get_kb_item('Host/Debian/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Debian');
var release = chomp(release);
if (! preg(pattern:"^(9)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 9.0', 'Debian ' + release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '9.0', 'prefix': 'squashfs-tools', 'reference': '1:4.3-3+deb9u2'},
    {'release': '9.0', 'prefix': 'squashfs-tools-dbg', 'reference': '1:4.3-3+deb9u2'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var release = NULL;
  var prefix = NULL;
  var reference = NULL;
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['prefix'])) prefix = package_array['prefix'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (release && prefix && reference) {
    if (deb_check(release:release, prefix:prefix, reference:reference)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'squashfs-tools / squashfs-tools-dbg');
}
