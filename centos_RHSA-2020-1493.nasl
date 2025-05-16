#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:1493.
##

include('compat.inc');

if (description)
{
  script_id(208557);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/10");

  script_cve_id(
    "CVE-2019-5108",
    "CVE-2019-14895",
    "CVE-2019-14901",
    "CVE-2019-15031",
    "CVE-2019-15099",
    "CVE-2019-15666",
    "CVE-2019-19922",
    "CVE-2019-20054",
    "CVE-2019-20095"
  );
  script_xref(name:"RHSA", value:"2020:1493");

  script_name(english:"CentOS 7 : kernel-alt (RHSA-2020:1493)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote CentOS Linux 7 host has packages installed that are affected by multiple vulnerabilities as referenced in the
RHSA-2020:1493 advisory.

  - A heap-based buffer overflow was discovered in the Linux kernel, all versions 3.x.x and 4.x.x before
    4.18.0, in Marvell WiFi chip driver. The flaw could occur when the station attempts a connection
    negotiation during the handling of the remote devices country settings. This could allow the remote device
    to cause a denial of service (system crash) or possibly execute arbitrary code. (CVE-2019-14895)

  - A heap overflow flaw was found in the Linux kernel, all versions 3.x.x and 4.x.x before 4.18.0, in Marvell
    WiFi chip driver. The vulnerability allows a remote attacker to cause a system crash, resulting in a
    denial of service, or execute arbitrary code. The highest threat with this vulnerability is with the
    availability of the system. If code execution occurs, the code will run with the permissions of root. This
    will affect both confidentiality and integrity of files on the system. (CVE-2019-14901)

  - In the Linux kernel through 5.2.14 on the powerpc platform, a local user can read vector registers of
    other users' processes via an interrupt. To exploit the venerability, a local user starts a transaction
    (via the hardware transactional memory instruction tbegin) and then accesses vector registers. At some
    point, the vector registers will be corrupted with the values from a different local Linux process,
    because MSR_TM_ACTIVE is misused in arch/powerpc/kernel/process.c. (CVE-2019-15031)

  - drivers/net/wireless/ath/ath10k/usb.c in the Linux kernel through 5.2.8 has a NULL pointer dereference via
    an incomplete address in an endpoint descriptor. (CVE-2019-15099)

  - An issue was discovered in the Linux kernel before 5.0.19. There is an out-of-bounds array access in
    __xfrm_policy_unlink, which will cause denial of service, because verify_newpolicy_info in
    net/xfrm/xfrm_user.c mishandles directory validation. (CVE-2019-15666)

  - kernel/sched/fair.c in the Linux kernel before 5.3.9, when cpu.cfs_quota_us is used (e.g., with
    Kubernetes), allows attackers to cause a denial of service against non-cpu-bound applications by
    generating a workload that triggers unwanted slice expiration, aka CID-de53fd7aedb1. (In other words,
    although this slice expiration would typically be seen with benign workloads, it is possible that an
    attacker could calculate how many stray requests are required to force an entire Kubernetes cluster into a
    low-performance state caused by slice expiration, and ensure that a DDoS attack sent that number of stray
    requests. An attack does not affect the stability of the kernel; it only causes mismanagement of
    application execution.) (CVE-2019-19922)

  - In the Linux kernel before 5.0.6, there is a NULL pointer dereference in drop_sysctl_table() in
    fs/proc/proc_sysctl.c, related to put_links, aka CID-23da9588037e. (CVE-2019-20054)

  - mwifiex_tm_cmd in drivers/net/wireless/marvell/mwifiex/cfg80211.c in the Linux kernel before 5.1.6 has
    some error-handling cases that did not free allocated hostcmd memory, aka CID-003b686ace82. This will
    cause a memory leak and denial of service. (CVE-2019-20095)

  - An exploitable denial-of-service vulnerability exists in the Linux kernel prior to mainline 5.3. An
    attacker could exploit this vulnerability by triggering AP to send IAPP location updates for stations
    before the required authentication process has completed. This could lead to different denial-of-service
    scenarios, either by causing CAM table attacks, or by leading to traffic flapping if faking already
    existing clients in other nearby APs of the same wireless infrastructure. An attacker can forge
    Authentication and Association Request packets to trigger this vulnerability. (CVE-2019-5108)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2020:1493");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-14901");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/16");
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
    {'reference':'kernel-4.14.0-115.19.1.el7a', 'cpu':'ppc64le', 'release':'CentOS-7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-abi-whitelists-4.14.0-115.19.1.el7a', 'cpu':'ppc64le', 'release':'CentOS-7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-bootwrapper-4.14.0-115.19.1.el7a', 'cpu':'ppc64le', 'release':'CentOS-7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-4.14.0-115.19.1.el7a', 'cpu':'ppc64le', 'release':'CentOS-7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-devel-4.14.0-115.19.1.el7a', 'cpu':'ppc64le', 'release':'CentOS-7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-devel-4.14.0-115.19.1.el7a', 'cpu':'ppc64le', 'release':'CentOS-7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-headers-4.14.0-115.19.1.el7a', 'cpu':'ppc64le', 'release':'CentOS-7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-4.14.0-115.19.1.el7a', 'cpu':'ppc64le', 'release':'CentOS-7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-libs-4.14.0-115.19.1.el7a', 'cpu':'ppc64le', 'release':'CentOS-7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-libs-devel-4.14.0-115.19.1.el7a', 'cpu':'ppc64le', 'release':'CentOS-7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perf-4.14.0-115.19.1.el7a', 'cpu':'ppc64le', 'release':'CentOS-7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-perf-4.14.0-115.19.1.el7a', 'cpu':'ppc64le', 'release':'CentOS-7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE}
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
