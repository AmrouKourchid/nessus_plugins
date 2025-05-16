#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2025:0771-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(218742);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/04");

  script_cve_id(
    "CVE-2023-4244",
    "CVE-2023-52923",
    "CVE-2024-35863",
    "CVE-2024-50199",
    "CVE-2024-53104",
    "CVE-2024-56600",
    "CVE-2024-56601",
    "CVE-2024-56623",
    "CVE-2024-56650",
    "CVE-2024-56658",
    "CVE-2024-56664",
    "CVE-2024-56759",
    "CVE-2024-57791",
    "CVE-2024-57798",
    "CVE-2024-57849",
    "CVE-2024-57893"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2025/02/26");
  script_xref(name:"SuSE", value:"SUSE-SU-2025:0771-1");

  script_name(english:"SUSE SLES15 Security Update : kernel (SUSE-SU-2025:0771-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 / SLES_SAP15 host has packages installed that are affected by multiple vulnerabilities as
referenced in the SUSE-SU-2025:0771-1 advisory.

    The SUSE Linux Enterprise 15 SP3 kernel was updated to receive various security bugfixes.

    The following security bugs were fixed:

    - CVE-2024-35863: Fixed potential UAF in is_valid_oplock_break() (bsc#1224763).
    - CVE-2024-50199: mm/swapfile: skip HugeTLB pages for unuse_vma (bsc#1233112).
    - CVE-2024-53104: media: uvcvideo: Skip parsing frames of type UVC_VS_UNDEFINED in uvc_parse_format
    (bsc#1234025).
    - CVE-2024-56600: net: inet6: do not leave a dangling sk pointer in inet6_create() (bsc#1235217).
    - CVE-2024-56601: net: inet: do not leave a dangling sk pointer in inet_create() (bsc#1235230).
    - CVE-2024-56623: scsi: qla2xxx: Fix use after free on unload (bsc#1235466).
    - CVE-2024-56650: netfilter: x_tables: fix LED ID check in led_tg_check() (bsc#1235430).
    - CVE-2024-56658: net: defer final 'struct net' free in netns dismantle (bsc#1235441).
    - CVE-2024-56664: bpf, sockmap: Fix race between element replace and close() (bsc#1235249).
    - CVE-2024-56759: btrfs: fix use-after-free when COWing tree bock and tracing is enabled (bsc#1235645).
    - CVE-2024-57791: net/smc: check return value of sock_recvmsg when draining clc data (bsc#1235759).
    - CVE-2024-57798: drm/dp_mst: Ensure mst_primary pointer is valid in drm_dp_mst_handle_up_req()
    (bsc#1235818).
    - CVE-2024-57849: s390/cpum_sf: Handle CPU hotplug remove during sampling (bsc#1235814).
    - CVE-2024-57893: ALSA: seq: oss: Fix races at processing SysEx messages (bsc#1235920).


Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215420");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224763");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231847");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233112");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234025");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235217");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235230");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235249");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235430");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235441");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235466");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235645");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235759");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235814");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235818");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235920");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236104");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237389");
  # https://lists.suse.com/pipermail/sle-security-updates/2025-March/020476.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7b40fba6");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-4244");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52923");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35863");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50199");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53104");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56600");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56601");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56623");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56650");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56658");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56664");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56759");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-57791");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-57798");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-57849");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-57893");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-57798");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/09/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/03/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cluster-md-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dlm-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gfs2-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-64kb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-64kb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-livepatch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-livepatch-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-5_3_18-150300_59_195-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-obs-build");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-preempt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-preempt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-zfcpdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ocfs2-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:reiserfs-kmp-default");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(SLES15|SLES_SAP15)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15 / SLES_SAP15', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(3)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP3", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP15" && (! preg(pattern:"^(3)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP15 SP3", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'kernel-default-5.3.18-150300.59.195.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'kernel-default-base-5.3.18-150300.59.195.1.150300.18.116.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'kernel-default-devel-5.3.18-150300.59.195.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'kernel-devel-5.3.18-150300.59.195.1', 'sp':'3', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'kernel-macros-5.3.18-150300.59.195.1', 'sp':'3', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'kernel-obs-build-5.3.18-150300.59.195.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'kernel-preempt-5.3.18-150300.59.195.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'kernel-preempt-devel-5.3.18-150300.59.195.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'kernel-source-5.3.18-150300.59.195.1', 'sp':'3', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'kernel-syms-5.3.18-150300.59.195.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'reiserfs-kmp-default-5.3.18-150300.59.195.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'kernel-64kb-5.3.18-150300.59.195.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3', 'sles-ltss-release-15.3']},
    {'reference':'kernel-64kb-devel-5.3.18-150300.59.195.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3', 'sles-ltss-release-15.3']},
    {'reference':'kernel-default-5.3.18-150300.59.195.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'kernel-default-5.3.18-150300.59.195.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'kernel-default-base-5.3.18-150300.59.195.1.150300.18.116.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'kernel-default-base-5.3.18-150300.59.195.1.150300.18.116.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'kernel-default-devel-5.3.18-150300.59.195.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'kernel-default-devel-5.3.18-150300.59.195.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'kernel-devel-5.3.18-150300.59.195.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3', 'sles-ltss-release-15.3']},
    {'reference':'kernel-macros-5.3.18-150300.59.195.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3', 'sles-ltss-release-15.3']},
    {'reference':'kernel-obs-build-5.3.18-150300.59.195.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'kernel-obs-build-5.3.18-150300.59.195.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'kernel-preempt-5.3.18-150300.59.195.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3', 'sles-ltss-release-15.3']},
    {'reference':'kernel-preempt-5.3.18-150300.59.195.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3', 'sles-ltss-release-15.3']},
    {'reference':'kernel-preempt-devel-5.3.18-150300.59.195.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3', 'sles-ltss-release-15.3']},
    {'reference':'kernel-preempt-devel-5.3.18-150300.59.195.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3', 'sles-ltss-release-15.3']},
    {'reference':'kernel-source-5.3.18-150300.59.195.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3', 'sles-ltss-release-15.3']},
    {'reference':'kernel-syms-5.3.18-150300.59.195.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'kernel-syms-5.3.18-150300.59.195.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'reiserfs-kmp-default-5.3.18-150300.59.195.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'reiserfs-kmp-default-5.3.18-150300.59.195.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'cluster-md-kmp-default-5.3.18-150300.59.195.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.3']},
    {'reference':'dlm-kmp-default-5.3.18-150300.59.195.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.3']},
    {'reference':'gfs2-kmp-default-5.3.18-150300.59.195.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.3']},
    {'reference':'ocfs2-kmp-default-5.3.18-150300.59.195.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.3']},
    {'reference':'kernel-default-livepatch-5.3.18-150300.59.195.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.3']},
    {'reference':'kernel-default-livepatch-devel-5.3.18-150300.59.195.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.3']},
    {'reference':'kernel-livepatch-5_3_18-150300_59_195-default-1-150300.7.3.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.3']},
    {'reference':'kernel-default-5.3.18-150300.59.195.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.3']},
    {'reference':'kernel-default-base-5.3.18-150300.59.195.1.150300.18.116.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.3']},
    {'reference':'kernel-default-devel-5.3.18-150300.59.195.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.3']},
    {'reference':'kernel-obs-build-5.3.18-150300.59.195.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.3']},
    {'reference':'kernel-syms-5.3.18-150300.59.195.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.3']},
    {'reference':'kernel-zfcpdump-5.3.18-150300.59.195.1', 'sp':'3', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.3']},
    {'reference':'reiserfs-kmp-default-5.3.18-150300.59.195.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.3']}
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
        if ('ltss' >< tolower(check)) ltss_caveat_required = TRUE;
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  var ltss_plugin_caveat = NULL;
  if(ltss_caveat_required) ltss_plugin_caveat = '\n' +
    'NOTE: This vulnerability check contains fixes that apply to\n' +
    'packages only available in SUSE Enterprise Linux Server LTSS\n' +
    'repositories. Access to these package security updates require\n' +
    'a paid SUSE LTSS subscription.\n';
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + ltss_plugin_caveat
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cluster-md-kmp-default / dlm-kmp-default / gfs2-kmp-default / etc');
}
