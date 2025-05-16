#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# Rocky Linux Security Advisory RLSA-2024:2353.
##

include('compat.inc');

if (description)
{
  script_id(235545);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/07");

  script_cve_id("CVE-2023-1579");
  script_xref(name:"RLSA", value:"2024:2353");

  script_name(english:"RockyLinux 9 : mingw components (RLSA-2024:2353)");

  script_set_attribute(attribute:"synopsis", value:
"The remote RockyLinux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote RockyLinux 9 host has packages installed that are affected by a vulnerability as referenced in the
RLSA-2024:2353 advisory.

    * binutils: Heap-buffer-overflow binutils-gdb/bfd/libbfd.c in bfd_getl64 (CVE-2023-1579)

Tenable has extracted the preceding description block directly from the RockyLinux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.rockylinux.org/RLSA-2024:2353");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2180905");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-1579");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/05/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/05/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:mingw-binutils-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:mingw-binutils-generic-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:mingw-crt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:mingw-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:mingw-filesystem-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:mingw-gcc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:mingw-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:mingw-libffi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:mingw-w64-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:mingw-w64-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:mingw-w64-tools-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:mingw-winpthreads");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:mingw-zlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:mingw32-binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:mingw32-binutils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:mingw32-cpp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:mingw32-cpp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:mingw32-crt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:mingw32-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:mingw32-gcc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:mingw32-gcc-c++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:mingw32-gcc-c++-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:mingw32-gcc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:mingw32-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:mingw32-libffi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:mingw32-libgcc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:mingw32-libstdc++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:mingw32-winpthreads");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:mingw32-winpthreads-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:mingw32-zlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:mingw32-zlib-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:mingw64-binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:mingw64-binutils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:mingw64-cpp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:mingw64-cpp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:mingw64-crt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:mingw64-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:mingw64-gcc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:mingw64-gcc-c++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:mingw64-gcc-c++-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:mingw64-gcc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:mingw64-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:mingw64-libffi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:mingw64-libgcc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:mingw64-libstdc++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:mingw64-winpthreads");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:mingw64-winpthreads-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:mingw64-zlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:mingw64-zlib-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rocky:linux:9");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Rocky Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RockyLinux/release", "Host/RockyLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RockyLinux/release');
if (isnull(os_release) || 'Rocky Linux' >!< os_release) audit(AUDIT_OS_NOT, 'Rocky Linux');
var os_ver = pregmatch(pattern: "Rocky(?: Linux)? release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Rocky Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^9([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'RockyLinux 9.x', 'Rocky Linux ' + os_ver);

if (!get_kb_item('Host/RockyLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('aarch64' >!< cpu && 'ppc' >!< cpu && 's390' >!< cpu && 'x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Rocky Linux', cpu);

var pkgs = [
    {'reference':'mingw-binutils-generic-2.41-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mingw-binutils-generic-2.41-3.el9', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mingw-binutils-generic-2.41-3.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mingw-binutils-generic-2.41-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mingw-binutils-generic-debuginfo-2.41-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mingw-binutils-generic-debuginfo-2.41-3.el9', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mingw-binutils-generic-debuginfo-2.41-3.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mingw-binutils-generic-debuginfo-2.41-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mingw-filesystem-base-148-3.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mingw-w64-tools-11.0.1-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mingw-w64-tools-debuginfo-11.0.1-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mingw-w64-tools-debugsource-11.0.1-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mingw32-binutils-2.41-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mingw32-binutils-2.41-3.el9', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mingw32-binutils-2.41-3.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mingw32-binutils-2.41-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mingw32-binutils-debuginfo-2.41-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mingw32-binutils-debuginfo-2.41-3.el9', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mingw32-binutils-debuginfo-2.41-3.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mingw32-binutils-debuginfo-2.41-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mingw32-cpp-13.2.1-7.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mingw32-cpp-13.2.1-7.el9', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mingw32-cpp-13.2.1-7.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mingw32-cpp-13.2.1-7.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mingw32-cpp-debuginfo-13.2.1-7.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mingw32-cpp-debuginfo-13.2.1-7.el9', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mingw32-cpp-debuginfo-13.2.1-7.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mingw32-cpp-debuginfo-13.2.1-7.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mingw32-crt-11.0.1-3.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mingw32-filesystem-148-3.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mingw32-gcc-13.2.1-7.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mingw32-gcc-13.2.1-7.el9', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mingw32-gcc-13.2.1-7.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mingw32-gcc-13.2.1-7.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mingw32-gcc-c++-13.2.1-7.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mingw32-gcc-c++-13.2.1-7.el9', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mingw32-gcc-c++-13.2.1-7.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mingw32-gcc-c++-13.2.1-7.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mingw32-gcc-c++-debuginfo-13.2.1-7.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mingw32-gcc-c++-debuginfo-13.2.1-7.el9', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mingw32-gcc-c++-debuginfo-13.2.1-7.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mingw32-gcc-c++-debuginfo-13.2.1-7.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mingw32-gcc-debuginfo-13.2.1-7.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mingw32-gcc-debuginfo-13.2.1-7.el9', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mingw32-gcc-debuginfo-13.2.1-7.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mingw32-gcc-debuginfo-13.2.1-7.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mingw32-headers-11.0.1-3.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mingw32-libffi-3.4.4-5.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mingw32-libgcc-13.2.1-7.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mingw32-libgcc-13.2.1-7.el9', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mingw32-libgcc-13.2.1-7.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mingw32-libgcc-13.2.1-7.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mingw32-libstdc++-13.2.1-7.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mingw32-winpthreads-11.0.1-3.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mingw32-winpthreads-static-11.0.1-3.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mingw32-zlib-1.3.1-1.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mingw32-zlib-static-1.3.1-1.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mingw64-binutils-2.41-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mingw64-binutils-2.41-3.el9', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mingw64-binutils-2.41-3.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mingw64-binutils-2.41-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mingw64-binutils-debuginfo-2.41-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mingw64-binutils-debuginfo-2.41-3.el9', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mingw64-binutils-debuginfo-2.41-3.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mingw64-binutils-debuginfo-2.41-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mingw64-cpp-13.2.1-7.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mingw64-cpp-13.2.1-7.el9', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mingw64-cpp-13.2.1-7.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mingw64-cpp-13.2.1-7.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mingw64-cpp-debuginfo-13.2.1-7.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mingw64-cpp-debuginfo-13.2.1-7.el9', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mingw64-cpp-debuginfo-13.2.1-7.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mingw64-cpp-debuginfo-13.2.1-7.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mingw64-crt-11.0.1-3.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mingw64-filesystem-148-3.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mingw64-gcc-13.2.1-7.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mingw64-gcc-13.2.1-7.el9', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mingw64-gcc-13.2.1-7.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mingw64-gcc-13.2.1-7.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mingw64-gcc-c++-13.2.1-7.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mingw64-gcc-c++-13.2.1-7.el9', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mingw64-gcc-c++-13.2.1-7.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mingw64-gcc-c++-13.2.1-7.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mingw64-gcc-c++-debuginfo-13.2.1-7.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mingw64-gcc-c++-debuginfo-13.2.1-7.el9', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mingw64-gcc-c++-debuginfo-13.2.1-7.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mingw64-gcc-c++-debuginfo-13.2.1-7.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mingw64-gcc-debuginfo-13.2.1-7.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mingw64-gcc-debuginfo-13.2.1-7.el9', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mingw64-gcc-debuginfo-13.2.1-7.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mingw64-gcc-debuginfo-13.2.1-7.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mingw64-headers-11.0.1-3.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mingw64-libffi-3.4.4-5.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mingw64-libgcc-13.2.1-7.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mingw64-libgcc-13.2.1-7.el9', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mingw64-libgcc-13.2.1-7.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mingw64-libgcc-13.2.1-7.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mingw64-libstdc++-13.2.1-7.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mingw64-winpthreads-11.0.1-3.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mingw64-winpthreads-static-11.0.1-3.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mingw64-zlib-1.3.1-1.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mingw64-zlib-static-1.3.1-1.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  var cves = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = 'Rocky-' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['cves'])) cves = package_array['cves'];
  if (reference && _release && (!exists_check || rpm_exists(release:_release, rpm:exists_check))) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj, cves:cves)) flag++;
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'mingw-binutils-generic / mingw-binutils-generic-debuginfo / etc');
}
