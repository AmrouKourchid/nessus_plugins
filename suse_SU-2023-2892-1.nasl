#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2023:2892-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(178589);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/20");

  script_cve_id(
    "CVE-2023-1249",
    "CVE-2023-1829",
    "CVE-2023-2430",
    "CVE-2023-3090",
    "CVE-2023-3111",
    "CVE-2023-3212",
    "CVE-2023-3220",
    "CVE-2023-3357",
    "CVE-2023-3358",
    "CVE-2023-3389",
    "CVE-2023-28866",
    "CVE-2023-35788",
    "CVE-2023-35823",
    "CVE-2023-35828",
    "CVE-2023-35829"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2023:2892-1");

  script_name(english:"SUSE SLES15 / openSUSE 15 Security Update : kernel (SUSE-SU-2023:2892-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 / SLES_SAP15 / openSUSE 15 host has packages installed that are affected by multiple
vulnerabilities as referenced in the SUSE-SU-2023:2892-1 advisory.

  - A use-after-free flaw was found in the Linux kernel's core dump subsystem. This flaw allows a local user
    to crash the system. Only if patch 390031c94211 (coredump: Use the vma snapshot in fill_files_note) not
    applied yet, then kernel could be affected. (CVE-2023-1249)

  - A use-after-free vulnerability in the Linux Kernel traffic control index filter (tcindex) can be exploited
    to achieve local privilege escalation. The tcindex_delete function which does not properly deactivate
    filters in case of a perfect hashes while deleting the underlying structure which can later lead to double
    freeing the structure. A local attacker user can use this vulnerability to elevate its privileges to root.
    We recommend upgrading past commit 8c710f75256bb3cf05ac7b1672c82b92c43f3d28. (CVE-2023-1829)

  - In the Linux kernel through 6.2.8, net/bluetooth/hci_sync.c allows out-of-bounds access because
    amp_init1[] and amp_init2[] are supposed to have an intentionally invalid element, but do not.
    (CVE-2023-28866)

  - A heap out-of-bounds write vulnerability in the Linux Kernel ipvlan network driver can be exploited to
    achieve local privilege escalation. The out-of-bounds write is caused by missing skb->cb initialization in
    the ipvlan network driver. The vulnerability is reachable if CONFIG_IPVLAN is enabled. We recommend
    upgrading past commit 90cbed5247439a966b645b34eb0a2e037836ea8e. (CVE-2023-3090)

  - A use after free vulnerability was found in prepare_to_relocate in fs/btrfs/relocation.c in btrfs in the
    Linux Kernel. This possible flaw can be triggered by calling btrfs_ioctl_balance() before calling
    btrfs_ioctl_defrag(). (CVE-2023-3111)

  - A NULL pointer dereference issue was found in the gfs2 file system in the Linux kernel. It occurs on
    corrupt gfs2 file systems when the evict code tries to reference the journal descriptor structure after it
    has been freed and set to NULL. A privileged local user could use this flaw to cause a kernel panic.
    (CVE-2023-3212)

  - An issue was discovered in the Linux kernel through 6.1-rc8. dpu_crtc_atomic_check in
    drivers/gpu/drm/msm/disp/dpu1/dpu_crtc.c lacks check of the return value of kzalloc() and will cause the
    NULL Pointer Dereference. (CVE-2023-3220)

  - A NULL pointer dereference flaw was found in the Linux kernel AMD Sensor Fusion Hub driver. This flaw
    allows a local user to crash the system. (CVE-2023-3357)

  - A null pointer dereference was found in the Linux kernel's Integrated Sensor Hub (ISH) driver. This issue
    could allow a local user to crash the system. (CVE-2023-3358)

  - A use-after-free vulnerability in the Linux Kernel io_uring subsystem can be exploited to achieve local
    privilege escalation. Racing a io_uring cancel poll request with a linked timeout can cause a UAF in a
    hrtimer. We recommend upgrading past commit ef7dfac51d8ed961b742218f526bd589f3900a59
    (4716c73b188566865bdd79c3a6709696a224ac04 for 5.10 stable and 0e388fce7aec40992eadee654193cad345d62663 for
    5.15 stable). (CVE-2023-3389)

  - An issue was discovered in fl_set_geneve_opt in net/sched/cls_flower.c in the Linux kernel before 6.3.7.
    It allows an out-of-bounds write in the flower classifier code via TCA_FLOWER_KEY_ENC_OPTS_GENEVE packets.
    This may result in denial of service or privilege escalation. (CVE-2023-35788)

  - An issue was discovered in the Linux kernel before 6.3.2. A use-after-free was found in saa7134_finidev in
    drivers/media/pci/saa7134/saa7134-core.c. (CVE-2023-35823)

  - An issue was discovered in the Linux kernel before 6.3.2. A use-after-free was found in
    renesas_usb3_remove in drivers/usb/gadget/udc/renesas_usb3.c. (CVE-2023-35828)

  - An issue was discovered in the Linux kernel before 6.3.2. A use-after-free was found in rkvdec_remove in
    drivers/staging/media/rkvdec/rkvdec.c. (CVE-2023-35829)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187829");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189998");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194869");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205758");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208410");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209039");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209780");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210335");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210565");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210584");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210853");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211014");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211346");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211400");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211410");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211794");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211852");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212051");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212265");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212350");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212405");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212445");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212448");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212456");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212494");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212495");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212504");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212513");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212540");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212556");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212561");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212563");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212564");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212584");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212592");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212603");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212605");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212606");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212619");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212685");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212701");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212741");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212835");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212838");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212842");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212848");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212861");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212869");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212892");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212961");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213010");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213011");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213012");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213013");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213014");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213015");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213016");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213017");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213018");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213019");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213020");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213021");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213024");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213025");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213032");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213034");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213035");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213036");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213037");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213038");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213039");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213040");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213041");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213087");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213088");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213089");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213090");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213092");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213093");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213094");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213095");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213096");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213098");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213099");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213100");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213102");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213103");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213104");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213105");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213106");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213107");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213108");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213109");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213110");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213111");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213112");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213113");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213114");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213116");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213134");
  # https://lists.suse.com/pipermail/sle-security-updates/2023-July/015533.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?872f5fd7");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1249");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1829");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-2430");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-28866");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-3090");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-3111");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-3212");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-3220");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-3357");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-3358");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-3389");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-35788");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-35823");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-35828");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-35829");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-35788");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/07/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-azure-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-devel-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-source-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms-azure");
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
if (isnull(os_release) || os_release !~ "^(SLED|SLES|SUSE)") audit(AUDIT_OS_NOT, "SUSE / openSUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)(?:_SAP)?\d+|SUSE([\d.]+))", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE / openSUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES15|SLES_SAP15|SUSE15\.5)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15 / SLES_SAP15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP5", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP15" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP15 SP5", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'kernel-azure-5.14.21-150500.33.6.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-azure-5.14.21-150500.33.6.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-azure-devel-5.14.21-150500.33.6.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-azure-devel-5.14.21-150500.33.6.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-devel-azure-5.14.21-150500.33.6.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-source-azure-5.14.21-150500.33.6.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-syms-azure-5.14.21-150500.33.6.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-syms-azure-5.14.21-150500.33.6.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-azure-5.14.21-150500.33.6.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-public-cloud-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-azure-5.14.21-150500.33.6.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-public-cloud-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-azure-devel-5.14.21-150500.33.6.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-public-cloud-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-azure-devel-5.14.21-150500.33.6.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-public-cloud-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-devel-azure-5.14.21-150500.33.6.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-public-cloud-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-source-azure-5.14.21-150500.33.6.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-public-cloud-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-syms-azure-5.14.21-150500.33.6.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-public-cloud-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-syms-azure-5.14.21-150500.33.6.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-public-cloud-release-15.5', 'sles-release-15.5']},
    {'reference':'cluster-md-kmp-azure-5.14.21-150500.33.6.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'cluster-md-kmp-azure-5.14.21-150500.33.6.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'dlm-kmp-azure-5.14.21-150500.33.6.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'dlm-kmp-azure-5.14.21-150500.33.6.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'gfs2-kmp-azure-5.14.21-150500.33.6.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'gfs2-kmp-azure-5.14.21-150500.33.6.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-azure-5.14.21-150500.33.6.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-azure-5.14.21-150500.33.6.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-azure-devel-5.14.21-150500.33.6.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-azure-devel-5.14.21-150500.33.6.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-azure-extra-5.14.21-150500.33.6.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-azure-extra-5.14.21-150500.33.6.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-azure-livepatch-devel-5.14.21-150500.33.6.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-azure-livepatch-devel-5.14.21-150500.33.6.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-azure-optional-5.14.21-150500.33.6.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-azure-optional-5.14.21-150500.33.6.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-azure-vdso-5.14.21-150500.33.6.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-devel-azure-5.14.21-150500.33.6.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-source-azure-5.14.21-150500.33.6.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-syms-azure-5.14.21-150500.33.6.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-syms-azure-5.14.21-150500.33.6.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kselftests-kmp-azure-5.14.21-150500.33.6.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kselftests-kmp-azure-5.14.21-150500.33.6.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'ocfs2-kmp-azure-5.14.21-150500.33.6.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'ocfs2-kmp-azure-5.14.21-150500.33.6.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'reiserfs-kmp-azure-5.14.21-150500.33.6.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'reiserfs-kmp-azure-5.14.21-150500.33.6.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cluster-md-kmp-azure / dlm-kmp-azure / gfs2-kmp-azure / etc');
}
