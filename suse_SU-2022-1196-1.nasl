#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2022:1196-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159749);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/13");

  script_cve_id(
    "CVE-2021-39713",
    "CVE-2021-45868",
    "CVE-2022-0001",
    "CVE-2022-0002",
    "CVE-2022-0812",
    "CVE-2022-0850",
    "CVE-2022-1016",
    "CVE-2022-1048",
    "CVE-2022-23036",
    "CVE-2022-23037",
    "CVE-2022-23038",
    "CVE-2022-23039",
    "CVE-2022-23040",
    "CVE-2022-23041",
    "CVE-2022-23042",
    "CVE-2022-23960",
    "CVE-2022-26490",
    "CVE-2022-26966",
    "CVE-2022-27666",
    "CVE-2022-28388",
    "CVE-2022-28389",
    "CVE-2022-28390"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2022:1196-1");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : kernel (SUSE-SU-2022:1196-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED12 / SLED_SAP12 / SLES12 / SLES_SAP12 host has packages installed that are affected by
multiple vulnerabilities as referenced in the SUSE-SU-2022:1196-1 advisory.

  - Product: AndroidVersions: Android kernelAndroid ID: A-173788806References: Upstream kernel
    (CVE-2021-39713)

  - In the Linux kernel before 5.15.3, fs/quota/quota_tree.c does not validate the block number in the quota
    tree (on disk). This can, for example, lead to a kernel/locking/rwsem.c use-after-free if there is a
    corrupted quota file. (CVE-2021-45868)

  - Non-transparent sharing of branch predictor selectors between contexts in some Intel(R) Processors may
    allow an authorized user to potentially enable information disclosure via local access. (CVE-2022-0001)

  - Non-transparent sharing of branch predictor within a context in some Intel(R) Processors may allow an
    authorized user to potentially enable information disclosure via local access. (CVE-2022-0002)

  - An information leak flaw was found in NFS over RDMA in the net/sunrpc/xprtrdma/rpc_rdma.c in the Linux
    Kernel. This flaw allows an attacker with normal user privileges to leak kernel information.
    (CVE-2022-0812)

  - A vulnerability was found in linux kernel, where an information leak occurs via ext4_extent_header to
    userspace. (CVE-2022-0850)

  - A flaw was found in the Linux kernel in net/netfilter/nf_tables_core.c:nft_do_chain, which can cause a
    use-after-free. This issue needs to handle 'return' with proper preconditions, as it can lead to a kernel
    information leak problem caused by a local, unprivileged attacker. (CVE-2022-1016)

  - A use-after-free flaw was found in the Linux kernel's sound subsystem in the way a user triggers
    concurrent calls of PCM hw_params. The hw_free ioctls or similar race condition happens inside ALSA PCM
    for other ioctls. This flaw allows a local user to crash or potentially escalate their privileges on the
    system. (CVE-2022-1048)

  - Linux PV device frontends vulnerable to attacks by backends T[his CNA information record relates to
    multiple CVEs; the text explains which aspects/vulnerabilities correspond to which CVE.] Several Linux PV
    device frontends are using the grant table interfaces for removing access rights of the backends in ways
    being subject to race conditions, resulting in potential data leaks, data corruption by malicious
    backends, and denial of service triggered by malicious backends: blkfront, netfront, scsifront and the
    gntalloc driver are testing whether a grant reference is still in use. If this is not the case, they
    assume that a following removal of the granted access will always succeed, which is not true in case the
    backend has mapped the granted page between those two operations. As a result the backend can keep access
    to the memory page of the guest no matter how the page will be used after the frontend I/O has finished.
    The xenbus driver has a similar problem, as it doesn't check the success of removing the granted access of
    a shared ring buffer. blkfront: CVE-2022-23036 netfront: CVE-2022-23037 scsifront: CVE-2022-23038
    gntalloc: CVE-2022-23039 xenbus: CVE-2022-23040 blkfront, netfront, scsifront, usbfront, dmabuf, xenbus,
    9p, kbdfront, and pvcalls are using a functionality to delay freeing a grant reference until it is no
    longer in use, but the freeing of the related data page is not synchronized with dropping the granted
    access. As a result the backend can keep access to the memory page even after it has been freed and then
    re-used for a different purpose. CVE-2022-23041 netfront will fail a BUG_ON() assertion if it fails to
    revoke access in the rx path. This will result in a Denial of Service (DoS) situation of the guest which
    can be triggered by the backend. CVE-2022-23042 (CVE-2022-23036, CVE-2022-23037, CVE-2022-23038,
    CVE-2022-23039, CVE-2022-23040, CVE-2022-23041, CVE-2022-23042)

  - Certain Arm Cortex and Neoverse processors through 2022-03-08 do not properly restrict cache speculation,
    aka Spectre-BHB. An attacker can leverage the shared branch history in the Branch History Buffer (BHB) to
    influence mispredicted branches. Then, cache allocation can allow the attacker to obtain sensitive
    information. (CVE-2022-23960)

  - st21nfca_connectivity_event_received in drivers/nfc/st21nfca/se.c in the Linux kernel through 5.16.12 has
    EVT_TRANSACTION buffer overflows because of untrusted length parameters. (CVE-2022-26490)

  - An issue was discovered in the Linux kernel before 5.16.12. drivers/net/usb/sr9700.c allows attackers to
    obtain sensitive information from heap memory via crafted frame lengths from a device. (CVE-2022-26966)

  - A heap buffer overflow flaw was found in IPsec ESP transformation code in net/ipv4/esp4.c and
    net/ipv6/esp6.c. This flaw allows a local attacker with a normal user privilege to overwrite kernel heap
    objects and may cause a local privilege escalation threat. (CVE-2022-27666)

  - usb_8dev_start_xmit in drivers/net/can/usb/usb_8dev.c in the Linux kernel through 5.17.1 has a double
    free. (CVE-2022-28388)

  - mcba_usb_start_xmit in drivers/net/can/usb/mcba_usb.c in the Linux kernel through 5.17.1 has a double
    free. (CVE-2022-28389)

  - ems_usb_start_xmit in drivers/net/can/usb/ems_usb.c in the Linux kernel through 5.17.1 has a double free.
    (CVE-2022-28390)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1065729");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1114648");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1180153");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184207");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189562");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191428");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191451");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191580");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192273");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193738");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194163");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194541");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194580");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194586");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194590");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194591");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194943");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195051");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195353");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195403");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195480");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195482");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196018");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196114");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196339");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196367");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196468");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196478");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196488");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196514");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196639");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196657");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196723");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196761");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196830");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196836");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196901");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196942");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196973");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196999");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197099");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197227");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197331");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197366");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197462");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197531");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197661");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197675");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197754");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197755");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197756");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197757");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197758");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197760");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197763");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197806");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197894");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197914");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198031");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198032");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198033");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-39713");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-45868");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-0001");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-0002");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-0812");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-0850");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1016");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1048");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-23036");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-23037");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-23038");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-23039");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-23040");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-23041");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-23042");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-23960");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-26490");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-26966");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-27666");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-28388");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-28389");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-28390");
  # https://lists.suse.com/pipermail/sle-security-updates/2022-April/010723.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0093bedb");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-1048");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-28390");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/15");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_12_14-122_116-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ocfs2-kmp-default");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'reference':'cluster-md-kmp-default-4.12.14-122.116.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12.5', 'sle-ha-release-12.5', 'sles-release-12.5']},
    {'reference':'dlm-kmp-default-4.12.14-122.116.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12.5', 'sle-ha-release-12.5', 'sles-release-12.5']},
    {'reference':'gfs2-kmp-default-4.12.14-122.116.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12.5', 'sle-ha-release-12.5', 'sles-release-12.5']},
    {'reference':'ocfs2-kmp-default-4.12.14-122.116.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12.5', 'sle-ha-release-12.5', 'sles-release-12.5']},
    {'reference':'kernel-default-4.12.14-122.116.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'kernel-default-base-4.12.14-122.116.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'kernel-default-devel-4.12.14-122.116.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'kernel-default-extra-4.12.14-122.116.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLED_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'kernel-default-extra-4.12.14-122.116.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'kernel-default-man-4.12.14-122.116.1', 'sp':'5', 'cpu':'s390x', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'kernel-devel-4.12.14-122.116.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'kernel-macros-4.12.14-122.116.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'kernel-obs-build-4.12.14-122.116.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'kernel-source-4.12.14-122.116.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'kernel-syms-4.12.14-122.116.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'kernel-default-kgraft-4.12.14-122.116.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-live-patching-release-12.5']},
    {'reference':'kernel-default-kgraft-devel-4.12.14-122.116.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-live-patching-release-12.5']},
    {'reference':'kgraft-patch-4_12_14-122_116-default-1-8.3.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-live-patching-release-12.5']},
    {'reference':'kernel-obs-build-4.12.14-122.116.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'kernel-default-extra-4.12.14-122.116.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLED12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sled-release-12.5', 'sles-release-12.5']},
    {'reference':'kernel-default-extra-4.12.14-122.116.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sled-release-12.5', 'sles-release-12.5']},
    {'reference':'kernel-default-4.12.14-122.116.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'kernel-default-base-4.12.14-122.116.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'kernel-default-devel-4.12.14-122.116.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'kernel-default-man-4.12.14-122.116.1', 'sp':'5', 'cpu':'s390x', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'kernel-devel-4.12.14-122.116.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'kernel-macros-4.12.14-122.116.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'kernel-source-4.12.14-122.116.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'kernel-syms-4.12.14-122.116.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']}
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
