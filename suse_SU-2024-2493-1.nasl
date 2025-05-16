#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2024:2493-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(202563);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/31");

  script_cve_id(
    "CVE-2021-47145",
    "CVE-2021-47201",
    "CVE-2021-47275",
    "CVE-2021-47438",
    "CVE-2021-47498",
    "CVE-2021-47520",
    "CVE-2021-47547",
    "CVE-2023-4244",
    "CVE-2023-52507",
    "CVE-2023-52683",
    "CVE-2023-52693",
    "CVE-2023-52753",
    "CVE-2023-52817",
    "CVE-2023-52818",
    "CVE-2023-52819",
    "CVE-2024-26635",
    "CVE-2024-26636",
    "CVE-2024-26880",
    "CVE-2024-35805",
    "CVE-2024-35819",
    "CVE-2024-35828",
    "CVE-2024-35947",
    "CVE-2024-36014",
    "CVE-2024-36941",
    "CVE-2024-38598",
    "CVE-2024-38619",
    "CVE-2024-39301",
    "CVE-2024-39475"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2024:2493-1");

  script_name(english:"SUSE SLES12 Security Update : kernel (SUSE-SU-2024:2493-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES12 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SUSE-SU-2024:2493-1 advisory.

    The SUSE Linux Enterprise 12 SP5 RT kernel was updated to receive various security bugfixes.


    The following security bugs were fixed:

    - CVE-2021-47145: btrfs: do not BUG_ON in link_to_fixup_dir (bsc#1222005).
    - CVE-2021-47201: iavf: free q_vectors before queues in iavf_disable_vf (bsc#1222792).
    - CVE-2021-47275: bcache: avoid oversized read request in cache missing code path (bsc#1224965).
    - CVE-2021-47438: net/mlx5e: nullify cq->dbg pointer in mlx5_debug_cq_remove() (bsc#1225229)
    - CVE-2021-47498: dm rq: do not queue request to blk-mq during DM suspend (bsc#1225357).
    - CVE-2021-47520: can: pch_can: pch_can_rx_normal: fix use after free (bsc#1225431).
    - CVE-2021-47547: net: tulip: de4x5: fix the problem that the array 'lp->phy' may be out of bound
    (bsc#1225505).
    - CVE-2023-4244: Fixed a use-after-free in the nf_tables component, which could be exploited to achieve
    local privilege escalation (bsc#1215420).
    - CVE-2023-52507: Fixed possible shift-out-of-bounds in nfc/nci (bsc#1220833).
    - CVE-2023-52683: ACPI: LPIT: Avoid u32 multiplication overflow (bsc#1224627).
    - CVE-2023-52693: ACPI: video: check for error while searching for backlight device parent (bsc#1224686).
    - CVE-2023-52753: drm/amd/display: Avoid NULL dereference of timing generator (bsc#1225478).
    - CVE-2023-52817: drm/amdgpu: Fix a null pointer access when the smc_rreg pointer is NULL (bsc#1225569).
    - CVE-2023-52818: drm/amd: Fix UBSAN array-index-out-of-bounds for SMU7 (bsc#1225530).
    - CVE-2023-52819: drm/amd: Fix UBSAN array-index-out-of-bounds for Polaris and Tonga (bsc#1225532).
    - CVE-2024-26635: llc: Drop support for ETH_P_TR_802_2 (bsc#1221656).
    - CVE-2024-26636: llc: make llc_ui_sendmsg() more robust against bonding changes (bsc#1221659).
    - CVE-2024-26880: dm: call the resume method on internal suspend (bsc#1223188).
    - CVE-2024-35805: dm snapshot: fix lockup in dm_exception_table_exit (bsc#1224743).
    - CVE-2024-35819: soc: fsl: qbman: Use raw spinlock for cgr_lock (bsc#1224683).
    - CVE-2024-35828: wifi: libertas: fix some memleaks in lbs_allocate_cmd_buffer() (bsc#1224622).
    - CVE-2024-35947: dyndbg: fix old BUG_ON in >control parser (bsc#1224647).
    - CVE-2024-36014: drm/arm/malidp: fix a possible null pointer dereference (bsc#1225593).
    - CVE-2024-36941: wifi: nl80211: do not free NULL coalescing rule (bsc#1225835).
    - CVE-2024-38598: md: fix resync softlockup when bitmap size is less than array size (bsc#1226757).
    - CVE-2024-38619: usb-storage: alauda: Check whether the media is initialized (bsc#1226861).
    - CVE-2024-39301: net/9p: fix uninit-value in p9_client_rpc() (bsc#1226994).
    - CVE-2024-39475: fbdev: savage: Handle err return when savagefb_check_var failed (bsc#1227435)


Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215420");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220833");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221656");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221659");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222005");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222792");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223021");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223188");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224622");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224627");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224647");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224683");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224686");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224743");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224965");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225229");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225357");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225431");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225478");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225505");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225530");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225532");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225569");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225593");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225835");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226757");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226861");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226994");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227407");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227435");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227487");
  script_set_attribute(attribute:"see_also", value:"https://lists.suse.com/pipermail/sle-updates/2024-July/036017.html");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47145");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47201");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47275");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47438");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47498");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47520");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47547");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-4244");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52507");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52683");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52693");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52753");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52817");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52818");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52819");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26635");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26636");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26880");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35805");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35819");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35828");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35947");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36014");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36941");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38598");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38619");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39301");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39475");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-52818");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/09/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cluster-md-kmp-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dlm-kmp-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gfs2-kmp-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-devel-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-rt-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-rt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-rt_debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-rt_debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-source-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ocfs2-kmp-rt");
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
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES12', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES12 SP5", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'cluster-md-kmp-rt-4.12.14-10.194.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Linux-Enterprise-RT-release-12.5']},
    {'reference':'dlm-kmp-rt-4.12.14-10.194.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Linux-Enterprise-RT-release-12.5']},
    {'reference':'gfs2-kmp-rt-4.12.14-10.194.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Linux-Enterprise-RT-release-12.5']},
    {'reference':'kernel-devel-rt-4.12.14-10.194.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Linux-Enterprise-RT-release-12.5']},
    {'reference':'kernel-rt-4.12.14-10.194.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Linux-Enterprise-RT-release-12.5']},
    {'reference':'kernel-rt-base-4.12.14-10.194.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Linux-Enterprise-RT-release-12.5']},
    {'reference':'kernel-rt-devel-4.12.14-10.194.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Linux-Enterprise-RT-release-12.5']},
    {'reference':'kernel-rt_debug-4.12.14-10.194.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Linux-Enterprise-RT-release-12.5']},
    {'reference':'kernel-rt_debug-devel-4.12.14-10.194.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Linux-Enterprise-RT-release-12.5']},
    {'reference':'kernel-source-rt-4.12.14-10.194.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Linux-Enterprise-RT-release-12.5']},
    {'reference':'kernel-syms-rt-4.12.14-10.194.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Linux-Enterprise-RT-release-12.5']},
    {'reference':'ocfs2-kmp-rt-4.12.14-10.194.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Linux-Enterprise-RT-release-12.5']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cluster-md-kmp-rt / dlm-kmp-rt / gfs2-kmp-rt / kernel-devel-rt / etc');
}
