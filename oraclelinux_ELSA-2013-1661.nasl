#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2013:1661 and 
# Oracle Linux Security Advisory ELSA-2013-1661 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(71110);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/22");

  script_cve_id("CVE-2012-4516", "CVE-2013-2561");
  script_bugtraq_id(55896, 58335);
  script_xref(name:"RHSA", value:"2013:1661");

  script_name(english:"Oracle Linux 6 : rdma / stack (ELSA-2013-1661)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 6 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2013-1661 advisory.

    ibutils
    [1.5.7-8]
    - Add the -output patch to have programs use /var/cache/ibutils
      instead of /tmp
      Resolves: bz958569

    infinipath-psm
    * Thu Jan 24 2013 Jay Fenlason <fenlason@redhat.com>
    - Put the udev rules file in the right place
      Resolves: rhbz866732
    - include a patch from upstream to fix undefined references
      Resolves: rhbz887730

    [3.0.1-115.1015_open.1]
    - New upstream releas
      Resolves: rhbz818789

    [ 2.9-926.1005_open.2]
    - Add the udev rules file to close
      Resolves: rhbz747406

    [2.9-926.1005_open.1]
    - New upstream version.
      Resolves: rhbz635915

    * Fri Nov 05 2010 Jay Fenlason <fenlason@redhat.com>
    - Include the -execstack patch to get libinfinipath.so correctly
      labeled as not executing the stack.
      Resolves: rhbz612936

    [1.13-2]
    - Use macros for lib and include directories, and include dist tag in
      release field.
    - Corrected License field.
    - Corrected Requires lines for libuuid.
    - Add Exclusive-arch x86_64
      Related: rhbz570274

    [1.13-1]
    - Initial build.

    libibverbs
    [1.1.7-1]
    - Update to latest upstream release
    - Remove patches that are now part of upstream
    - Fix ibv_srq_pingpong with negative value to -s option
    - Resolves: bz879191

    libmlx4
    [1.0.5-4.el6.1]
    - Fix dracut module for compatibility with RHEL6 version of dracut.
    - Resolves: bz789121

    [1.0.5-4]
    - Add dracut module
    - Fix URL

    [1.0.5-3]
    - Reduce the dependencies of the setup script even further, it no longer
      needs grep

    [1.0.5-2]
    - The setup script needs to have execute permissions

    [1.0.5-1]
    - Update to latest upstream
    - Drop awk based setup for a bash based setup, making including
      the setup code on an initramfs easier
    - Modernize spec file
    - Related: bz950915

    librdmacm
    [1.0.17-1]
    - Official 1.0.17 release
    - The fix to bug 866221 got kicked back as incomplete last time, fix
      it for real this time.
    - Intel adapters that use the qib driver don't like using inline data,
      so use a memory region that is registered instead
    - Resolves: bz866221, bz828071

    mpitests
    [3.2-9]
    - Backport fixes from RHEL-7
      Resolves: rhbz1002332

    [3.2-7]
    - include BuildRequires: hwloc-devel from RHEL-7.0
    - Add win_free patch to close
      Resolves: rhbz734023

    mstflint
    [3.0-0.6.g6961daa.1]
    - Update to newer tarball that resolves licensing issues with the last
      tarball
    - Related: bz818183

    [3.0-0.5.gff93670.1]
    - Update to latest upstream version, which includes ConnectIB support
    - Resolves: bz818183

    openmpi
    [1.5.4-2.0.1]
    - Obsolete openmpi-psm-devel for 32bit

    [1.5.4-2]
    - Fix the build process by getting rid of the -build patch
      and autogen to fix
      Resolves: rhbz749115

    perftest
    [2.0-2]
    - Fix rpmdiff detected error.  Upstream overrode our cflags so stack
      protector got turned off.
    - Related: bz806183

    [2.0-1]
    - Update to latest upstream release
    - We had to drop ib_clock_test program as no equivalent exists
      in the latest release
    - Resolves: bz806183, bz806185, bz830099

    [1.3.0-2]
    - Update to latest upstream release
    - No longer strip rocee related code out, we can compile with it now
    - Related: bz739138

    qperf
    [0.4.9-1.0.1]
    - Rebuild for ULN upgrade

    [0.4.9-1]
    - Update to latest upstream release
    - Resolves: bz814909, bz840269

    rdma
    [3.10-3.0.1]
    - Append mlx4_* module parameters when insmod the modules [orabug 17429249] (Joe Jin)
    - Delay load mlx4_* to prevent hung when start udev. [orabug 16897608] (Joe Jin)
    - Fix FMR load, persistent ib0 subinterfaces, remove kudzu dependency (Chien Yen)
    - Add SDP to rdma.conf and rdma.init (Chien Yen)
    - Support Mellanox OFED 1.5.5 (Chien Yen)

    [3.10-3]
    - Replace an errant usage of PARENTDEVICE with PHYSDEV in ifdown-ib
    - Related: bz990288

    [3.10-2]
    - Somehow during editing I accidentally deleted a single character from
      the post scriptlet.  rpmdiff caught it, now I'm fixing it.
    - Resolves: bz990288

    [3.10-1]
    - Bump version to match final kernel submission
    - Add support for P_Key interfaces to ifup-ib and ifdown-ib

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2013-1661.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-2561");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2012-4516");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/10/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ibutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ibutils-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ibutils-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:infinipath-psm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:infinipath-psm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libibverbs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libibverbs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libibverbs-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libibverbs-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libmlx4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libmlx4-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:librdmacm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:librdmacm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:librdmacm-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:librdmacm-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mpitests-mvapich");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mpitests-mvapich-psm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mpitests-mvapich2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mpitests-mvapich2-psm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mpitests-openmpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mstflint");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openmpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openmpi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perftest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qperf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rdma");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/OracleLinux')) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_release = get_kb_item("Host/RedHat/release");
if (isnull(os_release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:os_release)) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Oracle Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 6', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var pkgs = [
    {'reference':'ibutils-1.5.7-8.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ibutils-devel-1.5.7-8.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ibutils-libs-1.5.7-8.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'infinipath-psm-3.0.1-115.1015_open.2.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'infinipath-psm-devel-3.0.1-115.1015_open.2.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libibverbs-1.1.7-1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libibverbs-devel-1.1.7-1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libibverbs-devel-static-1.1.7-1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libibverbs-utils-1.1.7-1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libmlx4-1.0.5-4.el6.1', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libmlx4-static-1.0.5-4.el6.1', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'librdmacm-1.0.17-1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'librdmacm-devel-1.0.17-1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'librdmacm-static-1.0.17-1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'librdmacm-utils-1.0.17-1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mpitests-mvapich-3.2-9.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mpitests-mvapich-psm-3.2-9.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mpitests-mvapich2-3.2-9.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mpitests-mvapich2-psm-3.2-9.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mpitests-openmpi-3.2-9.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mstflint-3.0-0.6.g6961daa.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openmpi-1.5.4-2.0.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openmpi-devel-1.5.4-2.0.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perftest-2.0-2.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qperf-0.4.9-1.0.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rdma-3.10-3.0.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ibutils-1.5.7-8.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ibutils-devel-1.5.7-8.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ibutils-libs-1.5.7-8.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'infinipath-psm-3.0.1-115.1015_open.2.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'infinipath-psm-devel-3.0.1-115.1015_open.2.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libibverbs-1.1.7-1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libibverbs-devel-1.1.7-1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libibverbs-devel-static-1.1.7-1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libibverbs-utils-1.1.7-1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libmlx4-1.0.5-4.el6.1', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libmlx4-static-1.0.5-4.el6.1', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'librdmacm-1.0.17-1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'librdmacm-devel-1.0.17-1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'librdmacm-static-1.0.17-1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'librdmacm-utils-1.0.17-1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mpitests-mvapich-3.2-9.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mpitests-mvapich-psm-3.2-9.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mpitests-mvapich2-3.2-9.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mpitests-mvapich2-psm-3.2-9.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mpitests-openmpi-3.2-9.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mstflint-3.0-0.6.g6961daa.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openmpi-1.5.4-2.0.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openmpi-devel-1.5.4-2.0.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perftest-2.0-2.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qperf-0.4.9-1.0.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rdma-3.10-3.0.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE}
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
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = 'EL' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && _release) {
    if (exists_check) {
        if (rpm_exists(release:_release, rpm:exists_check) && rpm_check(release:_release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    } else {
        if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    }
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ibutils / ibutils-devel / ibutils-libs / etc');
}
