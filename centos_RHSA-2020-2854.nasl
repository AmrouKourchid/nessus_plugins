#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:2854.
##

include('compat.inc');

if (description)
{
  script_id(208526);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/09");

  script_cve_id(
    "CVE-2018-16884",
    "CVE-2019-9458",
    "CVE-2019-11811",
    "CVE-2019-15917",
    "CVE-2019-18808",
    "CVE-2019-19062",
    "CVE-2019-19767",
    "CVE-2019-20636",
    "CVE-2020-8834",
    "CVE-2020-10720",
    "CVE-2020-11565",
    "CVE-2020-12888"
  );
  script_xref(name:"RHSA", value:"2020:2854");

  script_name(english:"CentOS 7 : kernel-alt (RHSA-2020:2854)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote CentOS Linux 7 host has packages installed that are affected by multiple vulnerabilities as referenced in the
RHSA-2020:2854 advisory.

  - A flaw was found in the Linux kernel's NFS41+ subsystem. NFS41+ shares mounted in different network
    namespaces at the same time can make bc_svc_process() use wrong back-channel IDs and cause a use-after-
    free vulnerability. Thus a malicious container user can cause a host kernel memory corruption and a system
    panic. Due to the nature of the flaw, privilege escalation cannot be fully ruled out. (CVE-2018-16884)

  - An issue was discovered in the Linux kernel before 5.0.4. There is a use-after-free upon attempted read
    access to /proc/ioports after the ipmi_si module is removed, related to drivers/char/ipmi/ipmi_si_intf.c,
    drivers/char/ipmi/ipmi_si_mem_io.c, and drivers/char/ipmi/ipmi_si_port_io.c. (CVE-2019-11811)

  - An issue was discovered in the Linux kernel before 5.0.5. There is a use-after-free issue when
    hci_uart_register_dev() fails in hci_uart_set_proto() in drivers/bluetooth/hci_ldisc.c. (CVE-2019-15917)

  - A memory leak in the ccp_run_sha_cmd() function in drivers/crypto/ccp/ccp-ops.c in the Linux kernel
    through 5.3.9 allows attackers to cause a denial of service (memory consumption), aka CID-128c66429247.
    (CVE-2019-18808)

  - A memory leak in the crypto_report() function in crypto/crypto_user_base.c in the Linux kernel through
    5.3.11 allows attackers to cause a denial of service (memory consumption) by triggering
    crypto_report_alg() failures, aka CID-ffdde5932042. (CVE-2019-19062)

  - The Linux kernel before 5.4.2 mishandles ext4_expand_extra_isize, as demonstrated by use-after-free errors
    in __ext4_expand_extra_isize and ext4_xattr_set_entry, related to fs/ext4/inode.c and fs/ext4/super.c, aka
    CID-4ea99936a163. (CVE-2019-19767)

  - In the Linux kernel before 5.4.12, drivers/input/input.c has out-of-bounds writes via a crafted keycode
    table, as demonstrated by input_set_keycode, aka CID-cb222aed03d7. (CVE-2019-20636)

  - In the Android kernel in the video driver there is a use after free due to a race condition. This could
    lead to local escalation of privilege with no additional execution privileges needed. User interaction is
    not needed for exploitation. (CVE-2019-9458)

  - A flaw was found in the Linux kernel's implementation of GRO in versions before 5.2. This flaw allows an
    attacker with local access to crash the system. (CVE-2020-10720)

  - An issue was discovered in the Linux kernel through 5.6.2. mpol_parse_str in mm/mempolicy.c has a stack-
    based out-of-bounds write because an empty nodelist is mishandled during mount option parsing, aka CID-
    aa9f7d5172fa. NOTE: Someone in the security community disagrees that this is a vulnerability because the
    issue is a bug in parsing mount options which can only be specified by a privileged user, so triggering
    the bug does not grant any powers not already held. (CVE-2020-11565)

  - The VFIO PCI driver in the Linux kernel through 5.6.13 mishandles attempts to access disabled memory
    space. (CVE-2020-12888)

  - KVM in the Linux kernel on Power8 processors has a conflicting use of HSTATE_HOST_R1 to store r1 state in
    kvmppc_hv_entry plus in kvmppc_{save,restore}_tm, leading to a stack corruption. Because of this, an
    attacker with the ability run code in kernel space of a guest VM can cause the host kernel to panic. There
    were two commits that, according to the reporter, introduced the vulnerability: f024ee098476 (KVM: PPC:
    Book3S HV: Pull out TM state save/restore into separate procedures) 87a11bb6a7f7 (KVM: PPC: Book3S HV:
    Work around XER[SO] bug in fake suspend mode) The former landed in 4.8, the latter in 4.17. This was
    fixed without realizing the impact in 4.18 with the following three commits, though it's believed the
    first is the only strictly necessary commit: 6f597c6b63b6 (KVM: PPC: Book3S PR: Add guest MSR parameter
    for kvmppc_save_tm()/kvmppc_restore_tm()) 7b0e827c6970 (KVM: PPC: Book3S HV: Factor fake-suspend
    handling out of kvmppc_save/restore_tm) 009c872a8bc4 (KVM: PPC: Book3S PR: Move
    kvmppc_save_tm/kvmppc_restore_tm to separate file) (CVE-2020-8834)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2020:2854");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-20636");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-16884");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/07");
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
    {'reference':'kernel-4.14.0-115.26.1.el7a', 'cpu':'ppc64le', 'release':'CentOS-7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-abi-whitelists-4.14.0-115.26.1.el7a', 'cpu':'ppc64le', 'release':'CentOS-7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-bootwrapper-4.14.0-115.26.1.el7a', 'cpu':'ppc64le', 'release':'CentOS-7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-4.14.0-115.26.1.el7a', 'cpu':'ppc64le', 'release':'CentOS-7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-devel-4.14.0-115.26.1.el7a', 'cpu':'ppc64le', 'release':'CentOS-7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-devel-4.14.0-115.26.1.el7a', 'cpu':'ppc64le', 'release':'CentOS-7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-headers-4.14.0-115.26.1.el7a', 'cpu':'ppc64le', 'release':'CentOS-7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-4.14.0-115.26.1.el7a', 'cpu':'ppc64le', 'release':'CentOS-7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-libs-4.14.0-115.26.1.el7a', 'cpu':'ppc64le', 'release':'CentOS-7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-libs-devel-4.14.0-115.26.1.el7a', 'cpu':'ppc64le', 'release':'CentOS-7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perf-4.14.0-115.26.1.el7a', 'cpu':'ppc64le', 'release':'CentOS-7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-perf-4.14.0-115.26.1.el7a', 'cpu':'ppc64le', 'release':'CentOS-7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE}
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
