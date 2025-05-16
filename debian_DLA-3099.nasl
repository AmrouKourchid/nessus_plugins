#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3099. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(164678);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/22");

  script_cve_id(
    "CVE-2020-13253",
    "CVE-2020-15469",
    "CVE-2020-15859",
    "CVE-2020-25084",
    "CVE-2020-25085",
    "CVE-2020-25624",
    "CVE-2020-25625",
    "CVE-2020-25723",
    "CVE-2020-27617",
    "CVE-2020-27821",
    "CVE-2020-28916",
    "CVE-2020-29129",
    "CVE-2020-29443",
    "CVE-2020-35504",
    "CVE-2020-35505",
    "CVE-2021-3392",
    "CVE-2021-3416",
    "CVE-2021-3507",
    "CVE-2021-3527",
    "CVE-2021-3582",
    "CVE-2021-3607",
    "CVE-2021-3608",
    "CVE-2021-3682",
    "CVE-2021-3713",
    "CVE-2021-3748",
    "CVE-2021-3930",
    "CVE-2021-4206",
    "CVE-2021-4207",
    "CVE-2021-20181",
    "CVE-2021-20196",
    "CVE-2021-20203",
    "CVE-2021-20221",
    "CVE-2021-20257",
    "CVE-2022-26354",
    "CVE-2022-35414"
  );
  script_xref(name:"IAVB", value:"2020-B-0041-S");
  script_xref(name:"IAVB", value:"2020-B-0063-S");
  script_xref(name:"IAVB", value:"2020-B-0026-S");
  script_xref(name:"IAVB", value:"2020-B-0075-S");

  script_name(english:"Debian dla-3099 : qemu - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3099 advisory.

    - -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3099-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                          Abhijith PA
    September 05, 2022                            https://wiki.debian.org/LTS
    - -------------------------------------------------------------------------

    Package        : qemu
    Version        : 1:3.1+dfsg-8+deb10u9
    CVE ID         : CVE-2020-13253 CVE-2020-15469 CVE-2020-15859 CVE-2020-25084
                     CVE-2020-25085 CVE-2020-25624 CVE-2020-25625 CVE-2020-25723
                     CVE-2020-27617 CVE-2020-27821 CVE-2020-28916 CVE-2020-29129
                     CVE-2020-29443 CVE-2020-35504 CVE-2020-35505 CVE-2021-3392
                     CVE-2021-3416 CVE-2021-3507 CVE-2021-3527 CVE-2021-3582
                     CVE-2021-3607 CVE-2021-3608 CVE-2021-3682 CVE-2021-3713
                     CVE-2021-3748 CVE-2021-3930 CVE-2021-4206 CVE-2021-4207
                     CVE-2021-20181 CVE-2021-20196 CVE-2021-20203 CVE-2021-20221
                     CVE-2021-20257 CVE-2022-26354 CVE-2022-35414

    Multiple security issues were discovered in QEMU, a fast processor
    emulator, which could result in denial of service or the the execution
    of arbitrary code.

    For Debian 10 buster, these problems have been fixed in version
    1:3.1+dfsg-8+deb10u9.

    We recommend that you upgrade your qemu packages.

    For the detailed security status of qemu please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/qemu

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/qemu");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-13253");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-15469");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-15859");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-25084");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-25085");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-25624");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-25625");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-25723");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-27617");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-27821");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-28916");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-29129");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-29443");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-35504");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-35505");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-20181");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-20196");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-20203");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-20221");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-20257");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3392");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3416");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3507");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3527");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3582");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3607");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3608");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3682");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3713");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3748");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3930");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-4206");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-4207");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-26354");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-35414");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/qemu");
  script_set_attribute(attribute:"solution", value:
"Upgrade the qemu packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3748");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-35414");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-block-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-guest-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-system");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-system-arm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-system-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-system-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-system-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-system-mips");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-system-misc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-system-ppc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-system-sparc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-system-x86");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-user");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-user-binfmt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-user-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"II");
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
if (! preg(pattern:"^(10)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 10.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'qemu', 'reference': '1:3.1+dfsg-8+deb10u9'},
    {'release': '10.0', 'prefix': 'qemu-block-extra', 'reference': '1:3.1+dfsg-8+deb10u9'},
    {'release': '10.0', 'prefix': 'qemu-guest-agent', 'reference': '1:3.1+dfsg-8+deb10u9'},
    {'release': '10.0', 'prefix': 'qemu-kvm', 'reference': '1:3.1+dfsg-8+deb10u9'},
    {'release': '10.0', 'prefix': 'qemu-system', 'reference': '1:3.1+dfsg-8+deb10u9'},
    {'release': '10.0', 'prefix': 'qemu-system-arm', 'reference': '1:3.1+dfsg-8+deb10u9'},
    {'release': '10.0', 'prefix': 'qemu-system-common', 'reference': '1:3.1+dfsg-8+deb10u9'},
    {'release': '10.0', 'prefix': 'qemu-system-data', 'reference': '1:3.1+dfsg-8+deb10u9'},
    {'release': '10.0', 'prefix': 'qemu-system-gui', 'reference': '1:3.1+dfsg-8+deb10u9'},
    {'release': '10.0', 'prefix': 'qemu-system-mips', 'reference': '1:3.1+dfsg-8+deb10u9'},
    {'release': '10.0', 'prefix': 'qemu-system-misc', 'reference': '1:3.1+dfsg-8+deb10u9'},
    {'release': '10.0', 'prefix': 'qemu-system-ppc', 'reference': '1:3.1+dfsg-8+deb10u9'},
    {'release': '10.0', 'prefix': 'qemu-system-sparc', 'reference': '1:3.1+dfsg-8+deb10u9'},
    {'release': '10.0', 'prefix': 'qemu-system-x86', 'reference': '1:3.1+dfsg-8+deb10u9'},
    {'release': '10.0', 'prefix': 'qemu-user', 'reference': '1:3.1+dfsg-8+deb10u9'},
    {'release': '10.0', 'prefix': 'qemu-user-binfmt', 'reference': '1:3.1+dfsg-8+deb10u9'},
    {'release': '10.0', 'prefix': 'qemu-user-static', 'reference': '1:3.1+dfsg-8+deb10u9'},
    {'release': '10.0', 'prefix': 'qemu-utils', 'reference': '1:3.1+dfsg-8+deb10u9'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'qemu / qemu-block-extra / qemu-guest-agent / qemu-kvm / qemu-system / etc');
}
