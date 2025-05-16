#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2024:3793-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(209970);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/01");

  script_cve_id(
    "CVE-2021-47598",
    "CVE-2022-48651",
    "CVE-2022-48662",
    "CVE-2023-6546",
    "CVE-2023-52340",
    "CVE-2023-52502",
    "CVE-2023-52752",
    "CVE-2023-52846",
    "CVE-2024-23307",
    "CVE-2024-26585",
    "CVE-2024-26610",
    "CVE-2024-26622",
    "CVE-2024-26766",
    "CVE-2024-26828",
    "CVE-2024-26852",
    "CVE-2024-26923",
    "CVE-2024-26930",
    "CVE-2024-27398",
    "CVE-2024-35817",
    "CVE-2024-35861",
    "CVE-2024-35862",
    "CVE-2024-35863",
    "CVE-2024-35864",
    "CVE-2024-35867",
    "CVE-2024-35950",
    "CVE-2024-36899",
    "CVE-2024-36964",
    "CVE-2024-40954",
    "CVE-2024-41059"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2024:3793-1");

  script_name(english:"SUSE SLES15 Security Update : kernel (Live Patch 23 for SLE 15 SP4) (SUSE-SU-2024:3793-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 host has a package installed that is affected by multiple vulnerabilities as referenced in
the SUSE-SU-2024:3793-1 advisory.

    This update for the Linux Kernel 5.14.21-150400_24_108 fixes several issues.

    The following security issues were fixed:

    - CVE-2021-47598: sch_cake: do not call cake_destroy() from cake_init() (bsc#1227471).
    - CVE-2024-35863: Fixed potential UAF in is_valid_oplock_break() (bsc#1225011).
    - CVE-2023-52752: smb: client: fix use-after-free bug in cifs_debug_data_proc_show() (bsc#1225819).
    - CVE-2024-35862: Fixed potential UAF in smb2_is_network_name_deleted() (bsc#1225311).
    - CVE-2024-35867: Fixed potential UAF in cifs_stats_proc_show() (bsc#1225012).
    - CVE-2024-35864: Fixed potential UAF in smb2_is_valid_lease_break() (bsc#1225309).
    - Intermittent nfs mount failures (may be due to SUNRPC over UDP) (bsc#1231353)
    - CVE-2024-35861: Fixed potential UAF in cifs_signal_cifsd_for_reconnect() (bsc#1225312).
    - CVE-2024-36899: gpiolib: cdev: Fix use after free in lineinfo_changed_notify (bsc#1225739).
    - CVE-2024-40954: net: do not leave a dangling sk pointer, when socket creation fails (bsc#1227808)
    - CVE-2024-41059: hfsplus: fix uninit-value in copy_name (bsc#1228573).
    - CVE-2024-36964: fs/9p: only translate RWX permissions for plain 9P2000 (bsc#1226325).
    - CVE-2023-52846: hsr: Prevent use after free in prp_create_tagged_frame() (bsc#1225099).
    - CVE-2022-48662: Fixed a general protection fault (GPF) in i915_perf_open_ioctl (bsc#1223521).
    - CVE-2024-35817: Set gtt bound flag in amdgpu_ttm_gart_bind (bsc#1225313).
    - CVE-2024-27398: Fixed use-after-free bugs caused by sco_sock_timeout (bsc#1225013).
    - CVE-2024-35950: drm/client: Fully protect modes with dev->mode_config.mutex (bsc#1225310).
    - CVE-2024-26923: Fixed false-positive lockdep splat for spin_lock() in __unix_gc() (bsc#1223683).
    - CVE-2024-26930: Fixed double free of the ha->vp_map pointer (bsc#1223681).
    - CVE-2024-26828: Fixed underflow in parse_server_interfaces() (bsc#1223363).
    - CVE-2024-23307: Fixed Integer Overflow or Wraparound vulnerability in x86 and ARM md, raid, raid5
    modules (bsc#1220145).
    - CVE-2024-26852: Fixed use-after-free in ip6_route_mpath_notify() (bsc#1223059).
    - CVE-2024-26610: Fixed memory corruption in wifi/iwlwifi (bsc#1221302).
    - CVE-2022-48651: Fixed an out-of-bound bug in ipvlan caused by unset skb->mac_header (bsc#1223514).
    - CVE-2024-26766: Fixed SDMA off-by-one error in _pad_sdma_tx_descs() (bsc#1222882).
    - CVE-2023-52502: Fixed a race condition in nfc_llcp_sock_get() and nfc_llcp_sock_get_sn() (bsc#1220832).
    - CVE-2024-26585: Fixed race between tx work scheduling and socket close (bsc#1220211).
    - CVE-2023-6546: Fixed a race condition in the GSM 0710 tty multiplexor via the GSMIOC_SETCONF ioctl that
    could lead to local privilege escalation (bsc#1222685).
    - CVE-2024-26622: Fixed UAF write bug in tomoyo_write_control() (bsc#1220828).
    - CVE-2023-52340: Fixed a denial of service related to ICMPv6 'Packet Too Big' packets (bsc#1219296).

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219296");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220145");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220211");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220828");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220832");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221302");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222685");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222882");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223059");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223363");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223514");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223521");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223681");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223683");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225011");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225012");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225013");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225099");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225309");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225310");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225311");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225312");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225313");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225739");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225819");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226325");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227471");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228573");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228786");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231353");
  # https://lists.suse.com/pipermail/sle-security-updates/2024-October/019702.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ea07d4e6");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47598");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48651");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48662");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52340");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52502");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52752");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52846");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-6546");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-23307");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26585");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26610");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26622");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26766");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26828");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26852");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26923");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26930");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27398");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35817");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35861");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35862");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35863");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35864");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35867");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35950");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36899");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36964");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40954");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41059");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel-livepatch-5_14_21-150400_24_108-default package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-40954");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-5_14_21-150400_24_108-default");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
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
if (! preg(pattern:"^(SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15', 'SUSE (' + os_ver + ')');

var uname_r = get_kb_item("Host/uname-r");
if (empty_or_null(uname_r)) audit(AUDIT_UNKNOWN_APP_VER, "kernel");

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(4)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP4", os_ver + " SP" + service_pack);

var kernel_live_checks = [
  {
    'kernels': {
      '5.14.21-150400.24.108-default': {
        'pkgs': [
          {'reference':'kernel-livepatch-5_14_21-150400_24_108-default-10-150400.9.8.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.4']}
        ]
      }
    }
  }
];

var ltss_caveat_required = FALSE;
var flag = 0;
var kernel_affected = FALSE;
foreach var kernel_array ( kernel_live_checks ) {
  var kpatch_details = kernel_array['kernels'][uname_r];
  if (empty_or_null(kpatch_details)) continue;
  kernel_affected = TRUE;
  foreach var package_array ( kpatch_details['pkgs'] ) {
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
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

# No kpatch details found for the running kernel version
if (!kernel_affected) audit(AUDIT_INST_VER_NOT_VULN, 'kernel', uname_r);

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel-livepatch-5_14_21-150400_24_108-default');
}
