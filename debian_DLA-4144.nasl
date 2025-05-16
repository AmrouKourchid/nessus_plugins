#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-4144. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(235039);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/30");

  script_cve_id(
    "CVE-2023-1544",
    "CVE-2023-3019",
    "CVE-2023-5088",
    "CVE-2023-6693",
    "CVE-2024-3447"
  );
  script_xref(name:"IAVB", value:"2023-B-0058-S");
  script_xref(name:"IAVB", value:"2024-B-0022-S");
  script_xref(name:"IAVB", value:"2024-B-0070-S");

  script_name(english:"Debian dla-4144 : qemu - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-4144 advisory.

    -------------------------------------------------------------------------
    Debian LTS Advisory DLA-4144-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/               Santiago Ruano Rincn
    April 30, 2025                                https://wiki.debian.org/LTS
    -------------------------------------------------------------------------

    Package        : qemu
    Version        : 1:5.2+dfsg-11+deb11u4
    CVE ID         : CVE-2023-1544 CVE-2023-3019 CVE-2023-5088 CVE-2023-6693
                     CVE-2024-3447
    Debian Bug     : 1034179 1041102 1068821

    Multiple security issues were discovered in QEMU, a fast processor
    emulator, which could result in denial of service or information leak.

    CVE-2023-1544

        Potential out-of-bounds read and crash via VMWare's paravirtual RDMA device.

    CVE-2023-3019

        Use-after-free error in the e1000e NIC emulation.

    CVE-2023-5088

        IDE guest I/O operation addressed to an arbitrary disk offset may
        potentially allow to overwrite the VM's boot code.

    CVE-2023-6693

        Stack based buffer overflow in the virtio-net device emulation that may be
        exploited to cause information leak.

    CVE-2024-3447

        Heap-based buffer overflow in SDHCI device emulation.

    For Debian 11 bullseye, these problems have been fixed in version
    1:5.2+dfsg-11+deb11u4.

    We recommend that you upgrade your qemu packages.

    For the detailed security status of qemu please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/qemu

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS
    Attachment:
    signature.asc
    Description: PGP signature

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/qemu");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1544");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-3019");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-5088");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-6693");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-3447");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/qemu");
  script_set_attribute(attribute:"solution", value:
"Upgrade the qemu packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-5088");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-block-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-guest-agent");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
    {'release': '11.0', 'prefix': 'qemu', 'reference': '1:5.2+dfsg-11+deb11u4'},
    {'release': '11.0', 'prefix': 'qemu-block-extra', 'reference': '1:5.2+dfsg-11+deb11u4'},
    {'release': '11.0', 'prefix': 'qemu-guest-agent', 'reference': '1:5.2+dfsg-11+deb11u4'},
    {'release': '11.0', 'prefix': 'qemu-system', 'reference': '1:5.2+dfsg-11+deb11u4'},
    {'release': '11.0', 'prefix': 'qemu-system-arm', 'reference': '1:5.2+dfsg-11+deb11u4'},
    {'release': '11.0', 'prefix': 'qemu-system-common', 'reference': '1:5.2+dfsg-11+deb11u4'},
    {'release': '11.0', 'prefix': 'qemu-system-data', 'reference': '1:5.2+dfsg-11+deb11u4'},
    {'release': '11.0', 'prefix': 'qemu-system-gui', 'reference': '1:5.2+dfsg-11+deb11u4'},
    {'release': '11.0', 'prefix': 'qemu-system-mips', 'reference': '1:5.2+dfsg-11+deb11u4'},
    {'release': '11.0', 'prefix': 'qemu-system-misc', 'reference': '1:5.2+dfsg-11+deb11u4'},
    {'release': '11.0', 'prefix': 'qemu-system-ppc', 'reference': '1:5.2+dfsg-11+deb11u4'},
    {'release': '11.0', 'prefix': 'qemu-system-sparc', 'reference': '1:5.2+dfsg-11+deb11u4'},
    {'release': '11.0', 'prefix': 'qemu-system-x86', 'reference': '1:5.2+dfsg-11+deb11u4'},
    {'release': '11.0', 'prefix': 'qemu-user', 'reference': '1:5.2+dfsg-11+deb11u4'},
    {'release': '11.0', 'prefix': 'qemu-user-binfmt', 'reference': '1:5.2+dfsg-11+deb11u4'},
    {'release': '11.0', 'prefix': 'qemu-user-static', 'reference': '1:5.2+dfsg-11+deb11u4'},
    {'release': '11.0', 'prefix': 'qemu-utils', 'reference': '1:5.2+dfsg-11+deb11u4'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'qemu / qemu-block-extra / qemu-guest-agent / qemu-system / etc');
}
