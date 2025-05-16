#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2013:0509 and 
# Oracle Linux Security Advisory ELSA-2013-0509 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(68748);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/22");

  script_cve_id("CVE-2012-4517", "CVE-2012-4518");
  script_bugtraq_id(55890);
  script_xref(name:"RHSA", value:"2013:0509");

  script_name(english:"Oracle Linux 6 : rdma (ELSA-2013-0509)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 6 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2013-0509 advisory.

    ibacm
    [1.0.8-0.git7a3adb7]
    - Update to latest upstream via git repo
    - Resolves: bz866222, bz866223

    ibsim
    [0.5-7]
    - Bump and rebuild against latest opensm
    - Related: bz756396

    ibutils
    [1.5.7-7]
    - Bump and rebuild against latest opensm
    - Related: bz756396

    infiniband-diags
    [1.5.12-5]
    - Bump and rebuild against latest opensm
    - Pick up fixes done for rhel5.9
    - Related: bz756396

    [1.5.12-4]
    - Update the all_hcas patch to resolve several problems
    - Give a simple help message to the ibnodes script
    - Resolves: bz818606, bz847129

    infinipath-psm
    [3.0.1-115.1015_open.1]
    - New upstream releas
      Resolves: rhbz818789

    libibmad
    [1.3.9-1]
    - Update to latest upstream version (more SRIOV support)
    - Related: bz756396

    [1.3.8-1]
    - Update to latest upstream version (for FDR link speed support)
    - Related: bz750609

    [1.3.7-1]
    - Update to latest upstream version (1.3.4 -> 1.3.7)
    - Related: bz725016

    [1.3.4-1]
    - New upstream version

    [1.3.3-2]
    - ExcludeArch s390(x) as there's no hardware support there

    [1.3.3-1]
    - Update to latest upstream release

    [1.3.2-2]
    - Rebuilt for https://fedoraproject.org/wiki/Fedora_12_Mass_Rebuild

    [1.3.2-1]
    - Update to latest upstream version
    - Require the same version of libibumad as our version

    [1.3.1-1]
    - Update to latest upstream version

    [1.2.0-3]
    - Rebuilt against libtool 2.2

    [1.2.0-2]
    - Rebuilt for https://fedoraproject.org/wiki/Fedora_11_Mass_Rebuild

    [1.2.0-1]
    - Initial package for Fedora review process

    libibumad
    [1.3.8-1]
    - Update to latest upstream release (more SRIOV support)
    - Related: bz756396

    [1.3.7-1]
    - Update to latest upstream version (1.3.4 -> 1.3.7)
    - Related: bz725016

    [1.3.4-1]
    - New upstream release

    [1.3.3-2]
    - ExcludeArch s390(x) as there is no hardware support there

    [1.3.3-1]
    - Update to latest upstream version

    [1.3.2-3]
    - Rebuilt for https://fedoraproject.org/wiki/Fedora_12_Mass_Rebuild

    [1.3.2-2]
    - Forgot to remove both instances of the libibcommon requires
    - Add build requires on glibc-static

    [1.3.2-1]
    - Update to latest upstream version
    - Remove requirement on libibcommon since that library is no longer needed
    - Fix a problem with man page listing

    [1.3.1-1]
    - Update to latest upstream version

    [1.2.0-3]
    - Rebuilt against libtool 2.2

    [1.2.0-2]
    - Rebuilt for https://fedoraproject.org/wiki/Fedora_11_Mass_Rebuild

    [1.2.0-1]
    - Initial package for Fedora review process

    libibverbs
    [1.1.6-5]
    - Don't print link state on iWARP links as it's always invalid
    - Don't try to do ud transfers in excess of port MTU
    - Resolves: bz822781

    libmlx4
    [1.0.4-1]
    - Update to latest upstream version
    - Related: bz756396

    librdmacm
    [1.0.17-0.git4b5c1aa]
    - Pre-release version of 1.0.17
    - Resolves a CVE vulnerability between librdmacm and ibacm
    - Fixes various minor bugs in sample programs
    - Resolves: bz866221, bz816074

    opensm
    [3.3.15-1]
    - Update to latest upstream source (adds more SRIOV support)
    - Fix init script when no config files are present
    - Related: bz756396

    [3.3.13-1]
    - Update to latest upstream release
    - Add patch to support specifying subnet_prefix on command lien
    - Update init script to pass unique subnet_prefix's when using the GUID
      method of starting multiple instances
    - Fix up LSB init script headers
    - Resolves: bz754196

    [3.3.12-1]
    - Generate the opensm.conf file instead of shipping a static one as a source
    - Update to latest upstream release (FDR link speed support)
    - Resolves: bz750609

    [3.3.9-1]
    - Update to latest upstream version (3.3.5 -> 3.3.9)
    - Add /etc/sysconfig/opensm for use by opensm init script
    - Enable the ability to start more than one instance of opensm for multiple
      fabric support
    - Enable the ability to start opensm with a priority other than default for
      support of backup opensm instances
    - Related: bz725016
    - Resolves: bz633392

    [3.3.5-1]
    - Update to latest upstream release.  We need various defines in ib_types.h
      for the latest ibutils package to build properly, and the latest ibutils
      package is needed because we found licensing problems in the older
      tarballs during review.

    [3.3.3-2]
    - ExcludeArch s390(x) as there's no hardware support there

    [3.3.3-1]
    - Update to latest upstream release
    - Minor tweaks to init script for LSB compliance

    [3.3.2-2]
    - Rebuilt for https://fedoraproject.org/wiki/Fedora_12_Mass_Rebuild

    [3.3.2-1]
    - Update to latest upstream version

    [3.3.1-1]
    - Update to latest upstream version

    [3.2.1-3]
    - fix bare elifs to rebuild

    [3.2.1-2]
    - Rebuilt for https://fedoraproject.org/wiki/Fedora_11_Mass_Rebuild

    [3.2.1-1]
    - Initial package for Fedora review process

    rdma
    [3.6-1.0.2]
    - Add SDP to rdma.conf and rdma.init

    [3.6-1.0.1]
    - Support Mellanox OFED 1.5.5

    [3.6-1]
    - Bump version to match final kernel submission

    [3.6-0.rc5.1]
    - Bump version to match kernel update submitted for rhel6.4

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2013-0509.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-4518");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2012-4517");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/10/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ibacm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ibacm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ibsim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ibutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ibutils-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ibutils-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:infiniband-diags");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:infiniband-diags-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:infiniband-diags-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:infinipath-psm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:infinipath-psm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libibmad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libibmad-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libibmad-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libibumad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libibumad-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libibumad-static");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:opensm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:opensm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:opensm-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:opensm-static");
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
    {'reference':'ibacm-1.0.8-0.git7a3adb7.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ibacm-devel-1.0.8-0.git7a3adb7.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ibsim-0.5-7.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ibutils-1.5.7-7.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ibutils-devel-1.5.7-7.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ibutils-libs-1.5.7-7.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'infiniband-diags-1.5.12-5.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'infiniband-diags-devel-1.5.12-5.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'infiniband-diags-devel-static-1.5.12-5.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'infinipath-psm-3.0.1-115.1015_open.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'infinipath-psm-devel-3.0.1-115.1015_open.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libibmad-1.3.9-1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libibmad-devel-1.3.9-1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libibmad-static-1.3.9-1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libibumad-1.3.8-1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libibumad-devel-1.3.8-1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libibumad-static-1.3.8-1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libibverbs-1.1.6-5.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libibverbs-devel-1.1.6-5.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libibverbs-devel-static-1.1.6-5.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libibverbs-utils-1.1.6-5.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libmlx4-1.0.4-1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libmlx4-static-1.0.4-1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'librdmacm-1.0.17-0.git4b5c1aa.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'librdmacm-devel-1.0.17-0.git4b5c1aa.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'librdmacm-static-1.0.17-0.git4b5c1aa.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'librdmacm-utils-1.0.17-0.git4b5c1aa.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'opensm-3.3.15-1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'opensm-devel-3.3.15-1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'opensm-libs-3.3.15-1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'opensm-static-3.3.15-1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rdma-3.6-1.0.2.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ibacm-1.0.8-0.git7a3adb7.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ibacm-devel-1.0.8-0.git7a3adb7.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ibsim-0.5-7.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ibutils-1.5.7-7.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ibutils-devel-1.5.7-7.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ibutils-libs-1.5.7-7.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'infiniband-diags-1.5.12-5.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'infiniband-diags-devel-1.5.12-5.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'infiniband-diags-devel-static-1.5.12-5.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'infinipath-psm-3.0.1-115.1015_open.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'infinipath-psm-devel-3.0.1-115.1015_open.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libibmad-1.3.9-1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libibmad-devel-1.3.9-1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libibmad-static-1.3.9-1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libibumad-1.3.8-1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libibumad-devel-1.3.8-1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libibumad-static-1.3.8-1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libibverbs-1.1.6-5.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libibverbs-devel-1.1.6-5.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libibverbs-devel-static-1.1.6-5.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libibverbs-utils-1.1.6-5.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libmlx4-1.0.4-1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libmlx4-static-1.0.4-1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'librdmacm-1.0.17-0.git4b5c1aa.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'librdmacm-devel-1.0.17-0.git4b5c1aa.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'librdmacm-static-1.0.17-0.git4b5c1aa.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'librdmacm-utils-1.0.17-0.git4b5c1aa.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'opensm-3.3.15-1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'opensm-devel-3.3.15-1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'opensm-libs-3.3.15-1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'opensm-static-3.3.15-1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rdma-3.6-1.0.2.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_NOTE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ibacm / ibacm-devel / ibsim / etc');
}
