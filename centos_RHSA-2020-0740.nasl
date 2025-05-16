#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:0740.
##

include('compat.inc');

if (description)
{
  script_id(208605);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/09");

  script_cve_id(
    "CVE-2018-16871",
    "CVE-2019-3459",
    "CVE-2019-3460",
    "CVE-2019-11884",
    "CVE-2019-15030",
    "CVE-2019-15916",
    "CVE-2019-17666",
    "CVE-2019-18805"
  );
  script_xref(name:"RHSA", value:"2020:0740");

  script_name(english:"CentOS 7 : kernel-alt (RHSA-2020:0740)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote CentOS Linux 7 host has packages installed that are affected by multiple vulnerabilities as referenced in the
RHSA-2020:0740 advisory.

  - A flaw was found in the Linux kernel's NFS implementation, all versions 3.x and all versions 4.x up to
    4.20. An attacker, who is able to mount an exported NFS filesystem, is able to trigger a null pointer
    dereference by using an invalid NFS sequence. This can panic the machine and deny access to the NFS
    server. Any outstanding disk writes to the NFS server will be lost. (CVE-2018-16871)

  - The do_hidp_sock_ioctl function in net/bluetooth/hidp/sock.c in the Linux kernel before 5.0.15 allows a
    local user to obtain potentially sensitive information from kernel stack memory via a HIDPCONNADD command,
    because a name field may not end with a '\0' character. (CVE-2019-11884)

  - In the Linux kernel through 5.2.14 on the powerpc platform, a local user can read vector registers of
    other users' processes via a Facility Unavailable exception. To exploit the venerability, a local user
    starts a transaction (via the hardware transactional memory instruction tbegin) and then accesses vector
    registers. At some point, the vector registers will be corrupted with the values from a different local
    Linux process because of a missing arch/powerpc/kernel/process.c check. (CVE-2019-15030)

  - An issue was discovered in the Linux kernel before 5.0.1. There is a memory leak in
    register_queue_kobjects() in net/core/net-sysfs.c, which will cause denial of service. (CVE-2019-15916)

  - rtl_p2p_noa_ie in drivers/net/wireless/realtek/rtlwifi/ps.c in the Linux kernel through 5.3.6 lacks a
    certain upper-bound check, leading to a buffer overflow. (CVE-2019-17666)

  - An issue was discovered in net/ipv4/sysctl_net_ipv4.c in the Linux kernel before 5.0.11. There is a
    net/ipv4/tcp_input.c signed integer overflow in tcp_ack_update_rtt() when userspace writes a very large
    integer to /proc/sys/net/ipv4/tcp_min_rtt_wlen, leading to a denial of service or possibly unspecified
    other impact, aka CID-19fad20d15a6. (CVE-2019-18805)

  - A heap address information leak while using L2CAP_GET_CONF_OPT was discovered in the Linux kernel before
    5.1-rc1. (CVE-2019-3459)

  - A heap data infoleak in multiple locations including L2CAP_PARSE_CONF_RSP was found in the Linux kernel
    before 5.1-rc1. (CVE-2019-3460)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2020:0740");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-17666");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-18805");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/09");
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
    {'reference':'kernel-4.14.0-115.18.1.el7a', 'cpu':'ppc64le', 'release':'CentOS-7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-abi-whitelists-4.14.0-115.18.1.el7a', 'cpu':'ppc64le', 'release':'CentOS-7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-bootwrapper-4.14.0-115.18.1.el7a', 'cpu':'ppc64le', 'release':'CentOS-7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-4.14.0-115.18.1.el7a', 'cpu':'ppc64le', 'release':'CentOS-7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-devel-4.14.0-115.18.1.el7a', 'cpu':'ppc64le', 'release':'CentOS-7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-devel-4.14.0-115.18.1.el7a', 'cpu':'ppc64le', 'release':'CentOS-7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-headers-4.14.0-115.18.1.el7a', 'cpu':'ppc64le', 'release':'CentOS-7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-4.14.0-115.18.1.el7a', 'cpu':'ppc64le', 'release':'CentOS-7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-libs-4.14.0-115.18.1.el7a', 'cpu':'ppc64le', 'release':'CentOS-7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-libs-devel-4.14.0-115.18.1.el7a', 'cpu':'ppc64le', 'release':'CentOS-7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perf-4.14.0-115.18.1.el7a', 'cpu':'ppc64le', 'release':'CentOS-7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-perf-4.14.0-115.18.1.el7a', 'cpu':'ppc64le', 'release':'CentOS-7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE}
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
