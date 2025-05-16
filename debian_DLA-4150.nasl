#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-4150. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(235044);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/07");

  script_cve_id(
    "CVE-2019-14196",
    "CVE-2022-2347",
    "CVE-2022-30552",
    "CVE-2022-30767",
    "CVE-2022-30790",
    "CVE-2022-33103",
    "CVE-2022-33967",
    "CVE-2022-34835",
    "CVE-2024-57254",
    "CVE-2024-57255",
    "CVE-2024-57256",
    "CVE-2024-57257",
    "CVE-2024-57258",
    "CVE-2024-57259"
  );

  script_name(english:"Debian dla-4150 : u-boot - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-4150 advisory.

    -------------------------------------------------------------------------
    Debian LTS Advisory DLA-4150-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                       Daniel Leidert
    May 01, 2025                                  https://wiki.debian.org/LTS
    -------------------------------------------------------------------------

    Package        : u-boot
    Version        : 2021.01+dfsg-5+deb11u1
    CVE ID         : CVE-2019-14196 CVE-2022-2347 CVE-2022-30552 CVE-2022-30767
                     CVE-2022-30790 CVE-2022-33103 CVE-2022-33967 CVE-2022-34835
                     CVE-2024-57254 CVE-2024-57255 CVE-2024-57256 CVE-2024-57257
                     CVE-2024-57258 CVE-2024-57259
    Debian Bug     : 1014470 1014471 1014528 1014529 1014959 1098254


    Multiple vulnerabilties were discovered in u-boot, a boot loader for
    embedded systems.

    CVE-2022-2347

       An unchecked length field leading to a heap overflow.

    CVE-2022-30552 and CVE-2022-30790

       Buffer Overflow.

    CVE-2022-30767 (CVE-2019-14196)

       Unbounded memcpy with a failed length check, leading to a buffer
       overflow. This issue exists due to an incorrect fix for CVE-2019-
       14196.

    CVE-2022-33103

       Out-of-bounds write.

    CVE-2022-33967

       Heap-based buffer overflow vulnerability which may lead to a denial-
       of-service (DoS).

    CVE-2022-34835

       Integer signedness error and resultant stack-based buffer overflow.

    CVE-2024-57254

       Integer overflow.

    CVE-2024-57255

       Integer overflow.

    CVE-2024-57256

       Integer overflow.

    CVE-2024-57257

       Stack consumption issue.

    CVE-2024-57258

       Multiple integer overflows.

    CVE-2024-57259

       Off-by-one error resulting in heap memory corruption.


    For Debian 11 bullseye, these problems have been fixed in version
    2021.01+dfsg-5+deb11u1.

    We recommend that you upgrade your u-boot packages.

    For the detailed security status of u-boot please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/u-boot

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS
    Attachment:
    signature.asc
    Description: This is a digitally signed message part

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/u-boot");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-14196");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-2347");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-30552");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-30767");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-30790");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-33103");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-33967");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-34835");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-57254");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-57255");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-57256");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-57257");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-57258");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-57259");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/u-boot");
  script_set_attribute(attribute:"solution", value:
"Upgrade the u-boot packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-34835");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/05/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/05/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:u-boot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:u-boot-amlogic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:u-boot-exynos");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:u-boot-imx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:u-boot-mvebu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:u-boot-omap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:u-boot-qcom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:u-boot-qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:u-boot-rockchip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:u-boot-rpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:u-boot-sunxi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:u-boot-tegra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:u-boot-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'release': '11.0', 'prefix': 'u-boot', 'reference': '2021.01+dfsg-5+deb11u1'},
    {'release': '11.0', 'prefix': 'u-boot-amlogic', 'reference': '2021.01+dfsg-5+deb11u1'},
    {'release': '11.0', 'prefix': 'u-boot-exynos', 'reference': '2021.01+dfsg-5+deb11u1'},
    {'release': '11.0', 'prefix': 'u-boot-imx', 'reference': '2021.01+dfsg-5+deb11u1'},
    {'release': '11.0', 'prefix': 'u-boot-mvebu', 'reference': '2021.01+dfsg-5+deb11u1'},
    {'release': '11.0', 'prefix': 'u-boot-omap', 'reference': '2021.01+dfsg-5+deb11u1'},
    {'release': '11.0', 'prefix': 'u-boot-qcom', 'reference': '2021.01+dfsg-5+deb11u1'},
    {'release': '11.0', 'prefix': 'u-boot-qemu', 'reference': '2021.01+dfsg-5+deb11u1'},
    {'release': '11.0', 'prefix': 'u-boot-rockchip', 'reference': '2021.01+dfsg-5+deb11u1'},
    {'release': '11.0', 'prefix': 'u-boot-rpi', 'reference': '2021.01+dfsg-5+deb11u1'},
    {'release': '11.0', 'prefix': 'u-boot-sunxi', 'reference': '2021.01+dfsg-5+deb11u1'},
    {'release': '11.0', 'prefix': 'u-boot-tegra', 'reference': '2021.01+dfsg-5+deb11u1'},
    {'release': '11.0', 'prefix': 'u-boot-tools', 'reference': '2021.01+dfsg-5+deb11u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'u-boot / u-boot-amlogic / u-boot-exynos / u-boot-imx / u-boot-mvebu / etc');
}
