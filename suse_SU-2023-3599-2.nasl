#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2023:3599-2. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(181779);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/09/22");

  script_cve_id(
    "CVE-2022-38457",
    "CVE-2022-40133",
    "CVE-2023-2007",
    "CVE-2023-3610",
    "CVE-2023-3772",
    "CVE-2023-3863",
    "CVE-2023-4128",
    "CVE-2023-4133",
    "CVE-2023-4134",
    "CVE-2023-4147",
    "CVE-2023-4194",
    "CVE-2023-4273",
    "CVE-2023-4387",
    "CVE-2023-4459",
    "CVE-2023-4563",
    "CVE-2023-4569",
    "CVE-2023-20588",
    "CVE-2023-34319",
    "CVE-2023-37453",
    "CVE-2023-40283"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2023:3599-2");

  script_name(english:"SUSE SLES15 Security Update : kernel (SUSE-SU-2023:3599-2)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 host has a package installed that is affected by multiple vulnerabilities as referenced in
the SUSE-SU-2023:3599-2 advisory.

  - A use-after-free(UAF) vulnerability was found in function 'vmw_cmd_res_check' in
    drivers/gpu/vmxgfx/vmxgfx_execbuf.c in Linux kernel's vmwgfx driver with device file '/dev/dri/renderD128
    (or Dxxx)'. This flaw allows a local attacker with a user account on the system to gain privilege, causing
    a denial of service(DoS). (CVE-2022-38457)

  - A use-after-free(UAF) vulnerability was found in function 'vmw_execbuf_tie_context' in
    drivers/gpu/vmxgfx/vmxgfx_execbuf.c in Linux kernel's vmwgfx driver with device file '/dev/dri/renderD128
    (or Dxxx)'. This flaw allows a local attacker with a user account on the system to gain privilege, causing
    a denial of service(DoS). (CVE-2022-40133)

  - The specific flaw exists within the DPT I2O Controller driver. The issue results from the lack of proper
    locking when performing operations on an object. An attacker can leverage this in conjunction with other
    vulnerabilities to escalate privileges and execute arbitrary code in the context of the kernel.
    (CVE-2023-2007)

  - A division-by-zero error on some AMD processors can potentially return speculative data resulting in loss
    of confidentiality. (CVE-2023-20588)

  - 2023-09-14: CVE-2023-4015 was added to this advisory. (CVE-2023-34319)

  - A use-after-free vulnerability in the Linux kernel's netfilter: nf_tables component can be exploited to
    achieve local privilege escalation. Flaw in the error handling of bound chains causes a use-after-free in
    the abort path of NFT_MSG_NEWRULE. The vulnerability requires CAP_NET_ADMIN to be triggered. We recommend
    upgrading past commit 4bedf9eee016286c835e3d8fa981ddece5338795. (CVE-2023-3610)

  - An issue was discovered in the USB subsystem in the Linux kernel through 6.4.2. There is an out-of-bounds
    and crash in read_descriptors in drivers/usb/core/sysfs.c. (CVE-2023-37453)

  - A flaw was found in the Linux kernel's IP framework for transforming packets (XFRM subsystem). This issue
    may allow a malicious user with CAP_NET_ADMIN privileges to directly dereference a NULL pointer in
    xfrm_update_ae_params(), leading to a possible kernel crash and denial of service. (CVE-2023-3772)

  - A use-after-free flaw was found in nfc_llcp_find_local in net/nfc/llcp_core.c in NFC in the Linux kernel.
    This flaw allows a local user with special privileges to impact a kernel information leak issue.
    (CVE-2023-3863)

  - An issue was discovered in l2cap_sock_release in net/bluetooth/l2cap_sock.c in the Linux kernel before
    6.4.10. There is a use-after-free because the children of an sk are mishandled. (CVE-2023-40283)

  - A use-after-free flaw was found in net/sched/cls_fw.c in classifiers (cls_fw, cls_u32, and cls_route) in
    the Linux Kernel. This flaw allows a local attacker to perform a local privilege escalation due to
    incorrect handling of the existing filter, leading to a kernel information leak issue. (CVE-2023-4128)

  - A use-after-free vulnerability was found in the cxgb4 driver in the Linux kernel. The bug occurs when the
    cxgb4 device is detaching due to a possible rearming of the flower_stats_timer from the work queue. This
    flaw allows a local user to crash the system, causing a denial of service condition. (CVE-2023-4133)

  - A use-after-free flaw was found in the Linux kernel's Netfilter functionality when adding a rule with
    NFTA_RULE_CHAIN_ID. This flaw allows a local user to crash or escalate their privileges on the system.
    (CVE-2023-4147)

  - A flaw was found in the Linux kernel's TUN/TAP functionality. This issue could allow a local user to
    bypass network filters and gain unauthorized access to some resources. The original patches fixing
    CVE-2023-1076 are incorrect or incomplete. The problem is that the following upstream commits -
    a096ccca6e50 (tun: tun_chr_open(): correctly initialize socket uid), - 66b2c338adce (tap: tap_open():
    correctly initialize socket uid), pass inode->i_uid to sock_init_data_uid() as the last parameter and
    that turns out to not be accurate. (CVE-2023-4194)

  - A flaw was found in the exFAT driver of the Linux kernel. The vulnerability exists in the implementation
    of the file name reconstruction function, which is responsible for reading file name entries from a
    directory index and merging file name parts belonging to one file into a single long file name. Since the
    file name characters are copied into a stack variable, a local privileged attacker could use this flaw to
    overflow the kernel stack. (CVE-2023-4273)

  - A use-after-free flaw was found in vmxnet3_rq_alloc_rx_buf in drivers/net/vmxnet3/vmxnet3_drv.c in
    VMware's vmxnet3 ethernet NIC driver in the Linux Kernel. This issue could allow a local attacker to crash
    the system due to a double-free while cleaning up vmxnet3_rq_cleanup_all, which could also lead to a
    kernel information leak problem. (CVE-2023-4387)

  - A NULL pointer dereference flaw was found in vmxnet3_rq_cleanup in drivers/net/vmxnet3/vmxnet3_drv.c in
    the networking sub-component in vmxnet3 in the Linux Kernel. This issue may allow a local attacker with
    normal user privilege to cause a denial of service due to a missing sanity check during cleanup.
    (CVE-2023-4459)

  - A memory leak flaw was found in nft_set_catchall_flush in net/netfilter/nf_tables_api.c in the Linux
    Kernel. This issue may allow a local attacker to cause a double-deactivations of catchall elements, which
    results in a memory leak. (CVE-2023-4569)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1023051");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1120059");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1177719");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188885");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193629");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194869");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203329");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203330");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205462");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206453");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208902");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208949");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209284");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209799");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210048");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210448");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211220");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212091");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212142");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212423");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212526");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212857");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212873");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213026");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213123");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213546");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213580");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213601");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213666");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213733");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213757");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213759");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213916");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213921");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213927");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213946");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213949");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213968");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213970");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213971");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214000");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214019");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214073");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214120");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214149");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214180");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214233");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214238");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214285");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214297");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214299");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214305");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214350");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214368");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214370");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214371");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214372");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214380");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214386");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214392");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214393");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214397");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214404");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214428");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214451");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214659");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214661");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214727");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214729");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214742");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214743");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214756");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214976");
  # https://lists.suse.com/pipermail/sle-security-updates/2023-September/016283.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?afebbcf6");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-38457");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-40133");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-2007");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-20588");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-34319");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-3610");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-37453");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-3772");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-3863");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-40283");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-4128");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-4133");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-4134");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-4147");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-4194");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-4273");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-4387");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-4459");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-4563");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-4569");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel-livepatch-5_14_21-150500_13_14-rt package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-4147");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/09/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-5_14_21-150500_13_14-rt");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
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
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP5", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'kernel-livepatch-5_14_21-150500_13_14-rt-1-150500.11.3.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.5']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel-livepatch-5_14_21-150500_13_14-rt');
}
