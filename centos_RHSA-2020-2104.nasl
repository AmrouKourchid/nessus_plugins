#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:2104.
##

include('compat.inc');

if (description)
{
  script_id(208643);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/09");

  script_cve_id(
    "CVE-2017-18551",
    "CVE-2017-18595",
    "CVE-2019-9454",
    "CVE-2019-12614",
    "CVE-2019-15538",
    "CVE-2019-19447",
    "CVE-2019-19524",
    "CVE-2019-19768",
    "CVE-2020-9383",
    "CVE-2020-10711"
  );
  script_xref(name:"RHSA", value:"2020:2104");

  script_name(english:"CentOS 7 : kernel-alt (RHSA-2020:2104)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote CentOS Linux 7 host has packages installed that are affected by multiple vulnerabilities as referenced in the
RHSA-2020:2104 advisory.

  - An issue was discovered in drivers/i2c/i2c-core-smbus.c in the Linux kernel before 4.14.15. There is an
    out of bounds write in the function i2c_smbus_xfer_emulated. (CVE-2017-18551)

  - An issue was discovered in the Linux kernel before 4.14.11. A double free may be caused by the function
    allocate_trace_buffer in the file kernel/trace/trace.c. (CVE-2017-18595)

  - An issue was discovered in dlpar_parse_cc_property in arch/powerpc/platforms/pseries/dlpar.c in the Linux
    kernel through 5.1.6. There is an unchecked kstrdup of prop->name, which might allow an attacker to cause
    a denial of service (NULL pointer dereference and system crash). (CVE-2019-12614)

  - An issue was discovered in xfs_setattr_nonsize in fs/xfs/xfs_iops.c in the Linux kernel through 5.2.9. XFS
    partially wedges when a chgrp fails on account of being out of disk quota. xfs_setattr_nonsize is failing
    to unlock the ILOCK after the xfs_qm_vop_chown_reserve call fails. This is primarily a local DoS attack
    vector, but it might result as well in remote DoS if the XFS filesystem is exported for instance via NFS.
    (CVE-2019-15538)

  - In the Linux kernel 5.0.21, mounting a crafted ext4 filesystem image, performing some operations, and
    unmounting can lead to a use-after-free in ext4_put_super in fs/ext4/super.c, related to dump_orphan_list
    in fs/ext4/super.c. (CVE-2019-19447)

  - In the Linux kernel before 5.3.12, there is a use-after-free bug that can be caused by a malicious USB
    device in the drivers/input/ff-memless.c driver, aka CID-fa3a5a1880c9. (CVE-2019-19524)

  - In the Linux kernel 5.4.0-rc2, there is a use-after-free (read) in the __blk_add_trace function in
    kernel/trace/blktrace.c (which is used to fill out a blk_io_trace structure and place it in a per-cpu sub-
    buffer). (CVE-2019-19768)

  - In the Android kernel in i2c driver there is a possible out of bounds write due to memory corruption. This
    could lead to local escalation of privilege with System execution privileges needed. User interaction is
    not needed for exploitation. (CVE-2019-9454)

  - A NULL pointer dereference flaw was found in the Linux kernel's SELinux subsystem in versions before 5.7.
    This flaw occurs while importing the Commercial IP Security Option (CIPSO) protocol's category bitmap into
    the SELinux extensible bitmap via the' ebitmap_netlbl_import' routine. While processing the CIPSO
    restricted bitmap tag in the 'cipso_v4_parsetag_rbm' routine, it sets the security attribute to indicate
    that the category bitmap is present, even if it has not been allocated. This issue leads to a NULL pointer
    dereference issue while importing the same category bitmap into SELinux. This flaw allows a remote network
    user to crash the system kernel, resulting in a denial of service. (CVE-2020-10711)

  - An issue was discovered in the Linux kernel 3.16 through 5.5.6. set_fdc in drivers/block/floppy.c leads to
    a wait_til_ready out-of-bounds read because the FDC index is not checked for errors before assigning it,
    aka CID-2e90ca68b0d2. (CVE-2020-9383)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2020:2104");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-18595");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-19447");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-bootwrapper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/CentOS/release');
if (isnull(os_release) || 'CentOS' >!< os_release) audit(AUDIT_OS_NOT, 'CentOS');
var os_ver = pregmatch(pattern: "CentOS(?: Linux)? release ([0-9]+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'CentOS');
os_ver = os_ver[1];
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '7')) audit(AUDIT_OS_NOT, 'CentOS 7.x', 'CentOS ' + os_ver);

if (!get_kb_item('Host/CentOS/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'CentOS', cpu);

var pkgs = [
    {'reference':'kernel-4.14.0-115.21.2.el7a', 'cpu':'ppc64le', 'release':'CentOS-7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-abi-whitelists-4.14.0-115.21.2.el7a', 'cpu':'ppc64le', 'release':'CentOS-7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-bootwrapper-4.14.0-115.21.2.el7a', 'cpu':'ppc64le', 'release':'CentOS-7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-4.14.0-115.21.2.el7a', 'cpu':'ppc64le', 'release':'CentOS-7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-devel-4.14.0-115.21.2.el7a', 'cpu':'ppc64le', 'release':'CentOS-7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-devel-4.14.0-115.21.2.el7a', 'cpu':'ppc64le', 'release':'CentOS-7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-headers-4.14.0-115.21.2.el7a', 'cpu':'ppc64le', 'release':'CentOS-7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-4.14.0-115.21.2.el7a', 'cpu':'ppc64le', 'release':'CentOS-7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-libs-4.14.0-115.21.2.el7a', 'cpu':'ppc64le', 'release':'CentOS-7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-libs-devel-4.14.0-115.21.2.el7a', 'cpu':'ppc64le', 'release':'CentOS-7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perf-4.14.0-115.21.2.el7a', 'cpu':'ppc64le', 'release':'CentOS-7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-perf-4.14.0-115.21.2.el7a', 'cpu':'ppc64le', 'release':'CentOS-7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE}
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
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (reference && _release) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel / kernel-abi-whitelists / kernel-bootwrapper / etc');
}
