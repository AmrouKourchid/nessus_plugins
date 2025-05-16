#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:0174.
##

include('compat.inc');

if (description)
{
  script_id(208574);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/09");

  script_cve_id(
    "CVE-2018-3693",
    "CVE-2018-18559",
    "CVE-2019-3846",
    "CVE-2019-8912",
    "CVE-2019-10126",
    "CVE-2019-11487",
    "CVE-2019-14814",
    "CVE-2019-14815",
    "CVE-2019-14816",
    "CVE-2019-17133",
    "CVE-2019-18660"
  );
  script_xref(name:"RHSA", value:"2020:0174");

  script_name(english:"CentOS 7 : kernel-alt (RHSA-2020:0174)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote CentOS Linux 7 host has packages installed that are affected by multiple vulnerabilities as referenced in the
RHSA-2020:0174 advisory.

  - In the Linux kernel through 4.19, a use-after-free can occur due to a race condition between fanout_add
    from setsockopt and bind on an AF_PACKET socket. This issue exists because of the
    15fe076edea787807a7cdc168df832544b58eba6 incomplete fix for a race condition. The code mishandles a
    certain multithreaded case involving a packet_do_bind unregister action followed by a packet_notifier
    register action. Later, packet_release operates on only one of the two applicable linked lists. The
    attacker can achieve Program Counter control. (CVE-2018-18559)

  - Systems with microprocessors utilizing speculative execution and branch prediction may allow unauthorized
    disclosure of information to an attacker with local user access via a speculative buffer overflow and
    side-channel analysis. (CVE-2018-3693)

  - A flaw was found in the Linux kernel. A heap based buffer overflow in mwifiex_uap_parse_tail_ies function
    in drivers/net/wireless/marvell/mwifiex/ie.c might lead to memory corruption and possibly other
    consequences. (CVE-2019-10126)

  - The Linux kernel before 5.1-rc5 allows page->_refcount reference count overflow, with resultant use-after-
    free issues, if about 140 GiB of RAM exists. This is related to fs/fuse/dev.c, fs/pipe.c, fs/splice.c,
    include/linux/mm.h, include/linux/pipe_fs_i.h, kernel/trace/trace.c, mm/gup.c, and mm/hugetlb.c. It can
    occur with FUSE requests. (CVE-2019-11487)

  - There is heap-based buffer overflow in Linux kernel, all versions up to, excluding 5.3, in the marvell
    wifi chip driver in Linux kernel, that allows local users to cause a denial of service(system crash) or
    possibly execute arbitrary code. (CVE-2019-14814)

  - A vulnerability was found in Linux Kernel, where a Heap Overflow was found in mwifiex_set_wmm_params()
    function of Marvell Wifi Driver. (CVE-2019-14815)

  - There is heap-based buffer overflow in kernel, all versions up to, excluding 5.3, in the marvell wifi chip
    driver in Linux kernel, that allows local users to cause a denial of service(system crash) or possibly
    execute arbitrary code. (CVE-2019-14816)

  - In the Linux kernel through 5.3.2, cfg80211_mgd_wext_giwessid in net/wireless/wext-sme.c does not reject a
    long SSID IE, leading to a Buffer Overflow. (CVE-2019-17133)

  - The Linux kernel before 5.4.1 on powerpc allows Information Exposure because the Spectre-RSB mitigation is
    not in place for all applicable CPUs, aka CID-39e72bf96f58. This is related to
    arch/powerpc/kernel/entry_64.S and arch/powerpc/kernel/security.c. (CVE-2019-18660)

  - A flaw that allowed an attacker to corrupt memory and possibly escalate privileges was found in the
    mwifiex kernel module while connecting to a malicious wireless network. (CVE-2019-3846)

  - In the Linux kernel through 4.20.11, af_alg_release() in crypto/af_alg.c neglects to set a NULL value for
    a certain structure member, which leads to a use-after-free in sockfs_setattr. (CVE-2019-8912)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2020:0174");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-3846");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-17133");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/21");
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
    {'reference':'kernel-4.14.0-115.17.1.el7a', 'cpu':'ppc64le', 'release':'CentOS-7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-abi-whitelists-4.14.0-115.17.1.el7a', 'cpu':'ppc64le', 'release':'CentOS-7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-bootwrapper-4.14.0-115.17.1.el7a', 'cpu':'ppc64le', 'release':'CentOS-7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-4.14.0-115.17.1.el7a', 'cpu':'ppc64le', 'release':'CentOS-7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-devel-4.14.0-115.17.1.el7a', 'cpu':'ppc64le', 'release':'CentOS-7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-devel-4.14.0-115.17.1.el7a', 'cpu':'ppc64le', 'release':'CentOS-7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-headers-4.14.0-115.17.1.el7a', 'cpu':'ppc64le', 'release':'CentOS-7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-4.14.0-115.17.1.el7a', 'cpu':'ppc64le', 'release':'CentOS-7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-libs-4.14.0-115.17.1.el7a', 'cpu':'ppc64le', 'release':'CentOS-7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-libs-devel-4.14.0-115.17.1.el7a', 'cpu':'ppc64le', 'release':'CentOS-7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perf-4.14.0-115.17.1.el7a', 'cpu':'ppc64le', 'release':'CentOS-7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-perf-4.14.0-115.17.1.el7a', 'cpu':'ppc64le', 'release':'CentOS-7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE}
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
