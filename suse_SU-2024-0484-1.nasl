#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2024:0484-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(190650);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/30");

  script_cve_id(
    "CVE-2021-33631",
    "CVE-2023-6040",
    "CVE-2023-6356",
    "CVE-2023-6535",
    "CVE-2023-6536",
    "CVE-2023-6610",
    "CVE-2023-46838",
    "CVE-2023-47233",
    "CVE-2023-51042",
    "CVE-2023-51043",
    "CVE-2023-51780",
    "CVE-2023-51782",
    "CVE-2024-0340",
    "CVE-2024-0775",
    "CVE-2024-1086"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2024:0484-1");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/06/20");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : kernel (SUSE-SU-2024:0484-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED12 / SLED_SAP12 / SLES12 / SLES_SAP12 host has packages installed that are affected by
multiple vulnerabilities as referenced in the SUSE-SU-2024:0484-1 advisory.

  - Integer Overflow or Wraparound vulnerability in openEuler kernel on Linux (filesystem modules) allows
    Forced Integer Overflow.This issue affects openEuler kernel: from 4.19.90 before 4.19.90-2401.3, from
    5.10.0-60.18.0 before 5.10.0-183.0.0. (CVE-2021-33631)

  - Transmit requests in Xen's virtual network protocol can consist of multiple parts. While not really
    useful, except for the initial part any of them may be of zero length, i.e. carry no data at all. Besides
    a certain initial portion of the to be transferred data, these parts are directly translated into what
    Linux calls SKB fragments. Such converted request parts can, when for a particular SKB they are all of
    length zero, lead to a de-reference of NULL in core networking code. (CVE-2023-46838)

  - The brcm80211 component in the Linux kernel through 6.5.10 has a brcmf_cfg80211_detach use-after-free in
    the device unplugging (disconnect the USB by hotplug) code. For physically proximate attackers with local
    access, this could be exploited in a real world scenario. This is related to
    brcmf_cfg80211_escan_timeout_worker in drivers/net/wireless/broadcom/brcm80211/brcmfmac/cfg80211.c.
    (CVE-2023-47233)

  - In the Linux kernel before 6.4.12, amdgpu_cs_wait_all_fences in drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c has
    a fence use-after-free. (CVE-2023-51042)

  - In the Linux kernel before 6.4.5, drivers/gpu/drm/drm_atomic.c has a use-after-free during a race
    condition between a nonblocking atomic commit and a driver unload. (CVE-2023-51043)

  - An issue was discovered in the Linux kernel before 6.6.8. do_vcc_ioctl in net/atm/ioctl.c has a use-after-
    free because of a vcc_recvmsg race condition. (CVE-2023-51780)

  - An issue was discovered in the Linux kernel before 6.6.8. rose_ioctl in net/rose/af_rose.c has a use-
    after-free because of a rose_accept race condition. (CVE-2023-51782)

  - An out-of-bounds access vulnerability involving netfilter was reported and fixed as: f1082dd31fe4
    (netfilter: nf_tables: Reject tables of unsupported family); While creating a new netfilter table, lack of
    a safeguard against invalid nf_tables family (pf) values within `nf_tables_newtable` function enables an
    attacker to achieve out-of-bounds access. (CVE-2023-6040)

  - A flaw was found in the Linux kernel's NVMe driver. This issue may allow an unauthenticated malicious
    actor to send a set of crafted TCP packages when using NVMe over TCP, leading the NVMe driver to a NULL
    pointer dereference in the NVMe driver and causing kernel panic and a denial of service. (CVE-2023-6356)

  - A flaw was found in the Linux kernel's NVMe driver. This issue may allow an unauthenticated malicious
    actor to send a set of crafted TCP packages when using NVMe over TCP, leading the NVMe driver to a NULL
    pointer dereference in the NVMe driver, causing kernel panic and a denial of service. (CVE-2023-6535,
    CVE-2023-6536)

  - An out-of-bounds read vulnerability was found in smb2_dump_detail in fs/smb/client/smb2ops.c in the Linux
    Kernel. This issue could allow a local attacker to crash the system or leak internal kernel information.
    (CVE-2023-6610)

  - A vulnerability was found in vhost_new_msg in drivers/vhost/vhost.c in the Linux kernel, which does not
    properly initialize memory in messages passed between virtual guests and the host operating system in the
    vhost/vhost.c:vhost_new_msg() function. This issue can allow local privileged users to read some kernel
    memory contents when reading from the /dev/vhost-net device file. (CVE-2024-0340)

  - A use-after-free flaw was found in the __ext4_remount in fs/ext4/super.c in ext4 in the Linux kernel. This
    flaw allows a local user to cause an information leak problem while freeing the old quota file names
    before a potential failure, leading to a use-after-free. (CVE-2024-0775)

  - A use-after-free vulnerability in the Linux kernel's netfilter: nf_tables component can be exploited to
    achieve local privilege escalation. The nft_verdict_init() function allows positive values as drop error
    within the hook verdict, and hence the nf_hook_slow() function can cause a double free vulnerability when
    NF_DROP is issued with a drop error which resembles NF_ACCEPT. We recommend upgrading past commit
    f342de4e2f33e0e39165d8639387aa6c19dff660. (CVE-2024-1086)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1065729");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1108281");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1123986");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1141539");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1181674");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206889");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212152");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1216702");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1216989");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217525");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217946");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217987");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217988");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217989");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218689");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218713");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218730");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218752");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218757");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218768");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218836");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218968");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219022");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219053");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219120");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219128");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219412");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219434");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219445");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219446");
  # https://lists.suse.com/pipermail/sle-security-updates/2024-February/017920.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e115957e");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-33631");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-46838");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-47233");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-51042");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-51043");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-51780");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-51782");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-6040");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-6356");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-6535");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-6536");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-6610");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-0340");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-0775");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-1086");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-1086");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/06/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/17");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_12_14-122_194-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ocfs2-kmp-default");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'reference':'kernel-default-4.12.14-122.194.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'kernel-default-base-4.12.14-122.194.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'kernel-default-devel-4.12.14-122.194.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'kernel-default-extra-4.12.14-122.194.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLED_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'kernel-default-extra-4.12.14-122.194.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'kernel-default-man-4.12.14-122.194.1', 'sp':'5', 'cpu':'s390x', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'kernel-devel-4.12.14-122.194.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'kernel-macros-4.12.14-122.194.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'kernel-obs-build-4.12.14-122.194.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'kernel-source-4.12.14-122.194.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'kernel-syms-4.12.14-122.194.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'cluster-md-kmp-default-4.12.14-122.194.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-12.5']},
    {'reference':'dlm-kmp-default-4.12.14-122.194.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-12.5']},
    {'reference':'gfs2-kmp-default-4.12.14-122.194.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-12.5']},
    {'reference':'ocfs2-kmp-default-4.12.14-122.194.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-12.5']},
    {'reference':'kernel-default-kgraft-4.12.14-122.194.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-live-patching-release-12.5']},
    {'reference':'kernel-default-kgraft-devel-4.12.14-122.194.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-live-patching-release-12.5']},
    {'reference':'kgraft-patch-4_12_14-122_194-default-1-8.5.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-live-patching-release-12.5']},
    {'reference':'kernel-obs-build-4.12.14-122.194.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'kernel-default-extra-4.12.14-122.194.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLED12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'kernel-default-extra-4.12.14-122.194.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'kernel-default-4.12.14-122.194.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'kernel-default-base-4.12.14-122.194.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'kernel-default-devel-4.12.14-122.194.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'kernel-default-man-4.12.14-122.194.1', 'sp':'5', 'cpu':'s390x', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'kernel-devel-4.12.14-122.194.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'kernel-macros-4.12.14-122.194.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'kernel-source-4.12.14-122.194.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'kernel-syms-4.12.14-122.194.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']}
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
