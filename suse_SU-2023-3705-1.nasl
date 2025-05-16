#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2023:3705-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(181749);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/15");

  script_cve_id(
    "CVE-2022-36402",
    "CVE-2023-2007",
    "CVE-2023-3772",
    "CVE-2023-3812",
    "CVE-2023-3863",
    "CVE-2023-4128",
    "CVE-2023-4132",
    "CVE-2023-4133",
    "CVE-2023-4134",
    "CVE-2023-4194",
    "CVE-2023-4385",
    "CVE-2023-4387",
    "CVE-2023-4459",
    "CVE-2023-20588",
    "CVE-2023-34319",
    "CVE-2023-40283"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2023:3705-1");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : kernel (SUSE-SU-2023:3705-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED12 / SLED_SAP12 / SLES12 / SLES_SAP12 host has packages installed that are affected by
multiple vulnerabilities as referenced in the SUSE-SU-2023:3705-1 advisory.

  - An integer overflow vulnerability was found in vmwgfx driver in drivers/gpu/vmxgfx/vmxgfx_execbuf.c in GPU
    component of Linux kernel with device file '/dev/dri/renderD128 (or Dxxx)'. This flaw allows a local
    attacker with a user account on the system to gain privilege, causing a denial of service(DoS).
    (CVE-2022-36402)

  - The specific flaw exists within the DPT I2O Controller driver. The issue results from the lack of proper
    locking when performing operations on an object. An attacker can leverage this in conjunction with other
    vulnerabilities to escalate privileges and execute arbitrary code in the context of the kernel.
    (CVE-2023-2007)

  - A division-by-zero error on some AMD processors can potentially return speculative data resulting in loss
    of confidentiality. (CVE-2023-20588)

  - 2023-09-14: CVE-2023-4015 was added to this advisory. (CVE-2023-34319)

  - A flaw was found in the Linux kernel's IP framework for transforming packets (XFRM subsystem). This issue
    may allow a malicious user with CAP_NET_ADMIN privileges to directly dereference a NULL pointer in
    xfrm_update_ae_params(), leading to a possible kernel crash and denial of service. (CVE-2023-3772)

  - An out-of-bounds memory access flaw was found in the Linux kernel's TUN/TAP device driver functionality in
    how a user generates a malicious (too big) networking packet when napi frags is enabled. This flaw allows
    a local user to crash or potentially escalate their privileges on the system. (CVE-2023-3812)

  - A use-after-free flaw was found in nfc_llcp_find_local in net/nfc/llcp_core.c in NFC in the Linux kernel.
    This flaw allows a local user with special privileges to impact a kernel information leak issue.
    (CVE-2023-3863)

  - An issue was discovered in l2cap_sock_release in net/bluetooth/l2cap_sock.c in the Linux kernel before
    6.4.10. There is a use-after-free because the children of an sk are mishandled. (CVE-2023-40283)

  - A use-after-free flaw was found in net/sched/cls_fw.c in classifiers (cls_fw, cls_u32, and cls_route) in
    the Linux Kernel. This flaw allows a local attacker to perform a local privilege escalation due to
    incorrect handling of the existing filter, leading to a kernel information leak issue. (CVE-2023-4128)

  - A use-after-free vulnerability was found in the siano smsusb module in the Linux kernel. The bug occurs
    during device initialization when the siano device is plugged in. This flaw allows a local user to crash
    the system, causing a denial of service condition. (CVE-2023-4132)

  - A use-after-free vulnerability was found in the cxgb4 driver in the Linux kernel. The bug occurs when the
    cxgb4 device is detaching due to a possible rearming of the flower_stats_timer from the work queue. This
    flaw allows a local user to crash the system, causing a denial of service condition. (CVE-2023-4133)

  - A flaw was found in the Linux kernel's TUN/TAP functionality. This issue could allow a local user to
    bypass network filters and gain unauthorized access to some resources. The original patches fixing
    CVE-2023-1076 are incorrect or incomplete. The problem is that the following upstream commits -
    a096ccca6e50 (tun: tun_chr_open(): correctly initialize socket uid), - 66b2c338adce (tap: tap_open():
    correctly initialize socket uid), pass inode->i_uid to sock_init_data_uid() as the last parameter and
    that turns out to not be accurate. (CVE-2023-4194)

  - A NULL pointer dereference flaw was found in dbFree in fs/jfs/jfs_dmap.c in the journaling file system
    (JFS) in the Linux Kernel. This issue may allow a local attacker to crash the system due to a missing
    sanity check. (CVE-2023-4385)

  - A use-after-free flaw was found in vmxnet3_rq_alloc_rx_buf in drivers/net/vmxnet3/vmxnet3_drv.c in
    VMware's vmxnet3 ethernet NIC driver in the Linux Kernel. This issue could allow a local attacker to crash
    the system due to a double-free while cleaning up vmxnet3_rq_cleanup_all, which could also lead to a
    kernel information leak problem. (CVE-2023-4387)

  - A NULL pointer dereference flaw was found in vmxnet3_rq_cleanup in drivers/net/vmxnet3/vmxnet3_drv.c in
    the networking sub-component in vmxnet3 in the Linux Kernel. This issue may allow a local attacker with
    normal user privilege to cause a denial of service due to a missing sanity check during cleanup.
    (CVE-2023-4459)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1120059");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203517");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210327");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210448");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212051");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213543");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213546");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213601");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213666");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213899");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213904");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213906");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213908");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213910");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213911");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213912");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213921");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213927");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213969");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213970");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213971");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214019");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214149");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214157");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214209");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214233");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214299");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214335");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214348");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214350");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214451");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214453");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214752");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214928");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215028");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215032");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215034");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215035");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215036");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215037");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215038");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215041");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215046");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215049");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215057");
  # https://lists.suse.com/pipermail/sle-security-updates/2023-September/016233.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fb92eb80");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-36402");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-2007");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-20588");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-34319");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-3772");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-3812");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-3863");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-40283");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-4128");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-4132");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-4133");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-4134");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-4194");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-4385");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-4387");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-4459");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-40283");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/09/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cluster-md-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dlm-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gfs2-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-kgraft");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-kgraft-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-man");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-obs-build");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_12_14-122_176-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ocfs2-kmp-default");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)(?:_SAP)?\d+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLED12|SLED_SAP12|SLES12|SLES_SAP12)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLED12 / SLED_SAP12 / SLES12 / SLES_SAP12', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLED12" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED12 SP5", os_ver + " SP" + service_pack);
if (os_ver == "SLED_SAP12" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED_SAP12 SP5", os_ver + " SP" + service_pack);
if (os_ver == "SLES12" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES12 SP5", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP12" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP12 SP5", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'kernel-default-4.12.14-122.176.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'kernel-default-base-4.12.14-122.176.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'kernel-default-devel-4.12.14-122.176.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'kernel-default-extra-4.12.14-122.176.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLED_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'kernel-default-extra-4.12.14-122.176.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'kernel-default-man-4.12.14-122.176.1', 'sp':'5', 'cpu':'s390x', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'kernel-devel-4.12.14-122.176.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'kernel-macros-4.12.14-122.176.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'kernel-obs-build-4.12.14-122.176.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'kernel-source-4.12.14-122.176.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'kernel-syms-4.12.14-122.176.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'cluster-md-kmp-default-4.12.14-122.176.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-12.5']},
    {'reference':'dlm-kmp-default-4.12.14-122.176.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-12.5']},
    {'reference':'gfs2-kmp-default-4.12.14-122.176.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-12.5']},
    {'reference':'ocfs2-kmp-default-4.12.14-122.176.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-12.5']},
    {'reference':'kernel-default-kgraft-4.12.14-122.176.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-live-patching-release-12.5']},
    {'reference':'kernel-default-kgraft-devel-4.12.14-122.176.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-live-patching-release-12.5']},
    {'reference':'kgraft-patch-4_12_14-122_176-default-1-8.3.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-live-patching-release-12.5']},
    {'reference':'kernel-obs-build-4.12.14-122.176.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'kernel-default-extra-4.12.14-122.176.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLED12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'kernel-default-extra-4.12.14-122.176.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'kernel-default-4.12.14-122.176.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'kernel-default-base-4.12.14-122.176.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'kernel-default-devel-4.12.14-122.176.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'kernel-default-man-4.12.14-122.176.1', 'sp':'5', 'cpu':'s390x', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'kernel-devel-4.12.14-122.176.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'kernel-macros-4.12.14-122.176.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'kernel-source-4.12.14-122.176.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'kernel-syms-4.12.14-122.176.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']}
];

var ltss_caveat_required = FALSE;
var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var exists_check = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (exists_check) {
      var check_flag = 0;
      foreach var check (exists_check) {
        if (!rpm_exists(release:_release, rpm:check)) continue;
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cluster-md-kmp-default / dlm-kmp-default / gfs2-kmp-default / etc');
}
