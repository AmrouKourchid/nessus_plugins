#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3524. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(179933);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/22");

  script_cve_id("CVE-2022-40982");

  script_name(english:"Debian dla-3524 : hyperv-daemons - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by a vulnerability as referenced in the dla-3524
advisory.

    -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3524-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                        Ben Hutchings
    August 10, 2023                               https://wiki.debian.org/LTS
    -------------------------------------------------------------------------

    Package        : linux
    Version        : 4.19.289-2
    CVE ID         : CVE-2022-40982

    Daniel Moghimi discovered Gather Data Sampling (GDS), a hardware
    vulnerability for Intel CPUs which allows unprivileged speculative
    access to data which was previously stored in vector registers.

    This mitigation requires updated CPU microcode provided in the
    intel-microcode package.

    For details please refer to <https://downfall.page/> and
    <https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-
    guidance/technical-documentation/gather-data-sampling.html>.

    For Debian 10 buster, this problem has been fixed in version
    4.19.289-2.

    We recommend that you upgrade your linux packages.

    For the detailed security status of linux please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/linux

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS
    Attachment:
    signature.asc
    Description: PGP signature

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/linux");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-40982");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/linux");
  script_set_attribute(attribute:"solution", value:
"Upgrade the hyperv-daemons packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-40982");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/08/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/08/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/08/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:hyperv-daemons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libbpf-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libbpf4.19");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcpupower-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcpupower1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-compiler-gcc-8-arm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-compiler-gcc-8-x86");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-config-4.19");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-cpupower");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-doc-4.19");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-26-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-26-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-26-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-26-all-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-26-all-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-26-all-armhf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-26-all-i386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-26-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-26-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-26-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-26-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-26-cloud-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-26-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-26-common-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-26-rt-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-26-rt-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-26-rt-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-26-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-26-686-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-26-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-26-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-26-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-26-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-26-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-26-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-26-armmp-lpae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-26-cloud-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-26-rt-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-26-rt-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-26-rt-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-26-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-26-rt-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-amd64-signed-template");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-arm64-signed-template");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-i386-signed-template");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-kbuild-4.19");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-libc-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-perf-4.19");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-source-4.19");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-support-4.19.0-26");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usbip");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
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
if (! preg(pattern:"^(10)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 10.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'hyperv-daemons', 'reference': '4.19.289-2'},
    {'release': '10.0', 'prefix': 'libbpf-dev', 'reference': '4.19.289-2'},
    {'release': '10.0', 'prefix': 'libbpf4.19', 'reference': '4.19.289-2'},
    {'release': '10.0', 'prefix': 'libcpupower-dev', 'reference': '4.19.289-2'},
    {'release': '10.0', 'prefix': 'libcpupower1', 'reference': '4.19.289-2'},
    {'release': '10.0', 'prefix': 'linux-compiler-gcc-8-arm', 'reference': '4.19.289-2'},
    {'release': '10.0', 'prefix': 'linux-compiler-gcc-8-x86', 'reference': '4.19.289-2'},
    {'release': '10.0', 'prefix': 'linux-config-4.19', 'reference': '4.19.289-2'},
    {'release': '10.0', 'prefix': 'linux-cpupower', 'reference': '4.19.289-2'},
    {'release': '10.0', 'prefix': 'linux-doc-4.19', 'reference': '4.19.289-2'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-26-686', 'reference': '4.19.289-2'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-26-686-pae', 'reference': '4.19.289-2'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-26-all', 'reference': '4.19.289-2'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-26-all-amd64', 'reference': '4.19.289-2'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-26-all-arm64', 'reference': '4.19.289-2'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-26-all-armhf', 'reference': '4.19.289-2'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-26-all-i386', 'reference': '4.19.289-2'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-26-amd64', 'reference': '4.19.289-2'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-26-arm64', 'reference': '4.19.289-2'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-26-armmp', 'reference': '4.19.289-2'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-26-armmp-lpae', 'reference': '4.19.289-2'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-26-cloud-amd64', 'reference': '4.19.289-2'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-26-common', 'reference': '4.19.289-2'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-26-common-rt', 'reference': '4.19.289-2'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-26-rt-686-pae', 'reference': '4.19.289-2'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-26-rt-amd64', 'reference': '4.19.289-2'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-26-rt-arm64', 'reference': '4.19.289-2'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-26-rt-armmp', 'reference': '4.19.289-2'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-26-686-dbg', 'reference': '4.19.289-2'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-26-686-pae-dbg', 'reference': '4.19.289-2'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-26-amd64-dbg', 'reference': '4.19.289-2'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-26-arm64-dbg', 'reference': '4.19.289-2'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-26-armmp', 'reference': '4.19.289-2'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-26-armmp-dbg', 'reference': '4.19.289-2'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-26-armmp-lpae', 'reference': '4.19.289-2'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-26-armmp-lpae-dbg', 'reference': '4.19.289-2'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-26-cloud-amd64-dbg', 'reference': '4.19.289-2'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-26-rt-686-pae-dbg', 'reference': '4.19.289-2'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-26-rt-amd64-dbg', 'reference': '4.19.289-2'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-26-rt-arm64-dbg', 'reference': '4.19.289-2'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-26-rt-armmp', 'reference': '4.19.289-2'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-26-rt-armmp-dbg', 'reference': '4.19.289-2'},
    {'release': '10.0', 'prefix': 'linux-image-amd64-signed-template', 'reference': '4.19.289-2'},
    {'release': '10.0', 'prefix': 'linux-image-arm64-signed-template', 'reference': '4.19.289-2'},
    {'release': '10.0', 'prefix': 'linux-image-i386-signed-template', 'reference': '4.19.289-2'},
    {'release': '10.0', 'prefix': 'linux-kbuild-4.19', 'reference': '4.19.289-2'},
    {'release': '10.0', 'prefix': 'linux-libc-dev', 'reference': '4.19.289-2'},
    {'release': '10.0', 'prefix': 'linux-perf-4.19', 'reference': '4.19.289-2'},
    {'release': '10.0', 'prefix': 'linux-source-4.19', 'reference': '4.19.289-2'},
    {'release': '10.0', 'prefix': 'linux-support-4.19.0-26', 'reference': '4.19.289-2'},
    {'release': '10.0', 'prefix': 'usbip', 'reference': '4.19.289-2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'hyperv-daemons / libbpf-dev / libbpf4.19 / libcpupower-dev / etc');
}
