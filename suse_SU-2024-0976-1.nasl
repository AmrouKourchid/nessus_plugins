#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2024:0976-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(192501);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/13");

  script_cve_id(
    "CVE-2019-25162",
    "CVE-2020-36777",
    "CVE-2020-36784",
    "CVE-2021-46906",
    "CVE-2021-46915",
    "CVE-2021-46921",
    "CVE-2021-46924",
    "CVE-2021-46929",
    "CVE-2021-46932",
    "CVE-2021-46953",
    "CVE-2021-46974",
    "CVE-2021-46991",
    "CVE-2021-46992",
    "CVE-2021-47013",
    "CVE-2021-47054",
    "CVE-2021-47076",
    "CVE-2021-47077",
    "CVE-2021-47078",
    "CVE-2022-48627",
    "CVE-2023-28746",
    "CVE-2023-35827",
    "CVE-2023-46343",
    "CVE-2023-52340",
    "CVE-2023-52429",
    "CVE-2023-52443",
    "CVE-2023-52445",
    "CVE-2023-52449",
    "CVE-2023-52451",
    "CVE-2023-52464",
    "CVE-2023-52475",
    "CVE-2023-52478",
    "CVE-2023-52482",
    "CVE-2023-52502",
    "CVE-2023-52530",
    "CVE-2023-52531",
    "CVE-2023-52532",
    "CVE-2023-52574",
    "CVE-2023-52597",
    "CVE-2023-52605",
    "CVE-2024-0607",
    "CVE-2024-1151",
    "CVE-2024-23849",
    "CVE-2024-23851",
    "CVE-2024-26585",
    "CVE-2024-26595",
    "CVE-2024-26600",
    "CVE-2024-26622"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2024:0976-1");

  script_name(english:"SUSE SLES12 Security Update : kernel (SUSE-SU-2024:0976-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES12 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SUSE-SU-2024:0976-1 advisory.

    The SUSE Linux Enterprise SLE12SP5 RT kernel was updated to receive various security and bugfixes.


    The following security bugs were fixed:

    - CVE-2019-25162: Fixed a potential use after free (bsc#1220409).
    - CVE-2020-36777: Fixed a memory leak in dvb_media_device_free() (bsc#1220526).
    - CVE-2020-36784: Fixed reference leak when pm_runtime_get_sync fails (bsc#1220570).
    - CVE-2021-46906: Fixed an info leak in hid_submit_ctrl (bsc#1220421).
    - CVE-2021-46915: Fixed a bug to avoid possible divide error in nft_limit_init (bsc#1220436).
    - CVE-2021-46921: Fixed ordering in queued_write_lock_slowpath (bsc#1220468).
    - CVE-2021-46924: Fixed fix memory leak in device probe and remove (bsc#1220459)
    - CVE-2021-46932: Fixed missing work initialization before device registration (bsc#1220444)
    - CVE-2021-46953: Fixed a corruption in interrupt mappings on watchdow probe failure (bsc#1220599).
    - CVE-2021-46991: Fixed a use-after-free in i40e_client_subtask (bsc#1220575).
    - CVE-2021-46992: Fixed a bug to avoid overflows in nft_hash_buckets (bsc#1220638).
    - CVE-2021-47013: Fixed a use after free in emac_mac_tx_buf_send (bsc#1220641).
    - CVE-2021-47054: Fixed a bug to put child node before return (bsc#1220767).
    - CVE-2021-47076: Fixed a bug by returning CQE error if invalid lkey was supplied (bsc#1220860)
    - CVE-2021-47077: Fixed a NULL pointer dereference when in shost_data (bsc#1220861).
    - CVE-2021-47078: Fixed a bug by clearing all QP fields if creation failed (bsc#1220863)
    - CVE-2022-48627: Fixed a memory overlapping when deleting chars in the buffer (bsc#1220845).
    - CVE-2023-28746: Fixed Register File Data Sampling (bsc#1213456).
    - CVE-2023-35827: Fixed a use-after-free issue in ravb_tx_timeout_work() (bsc#1212514).
    - CVE-2023-46343: Fixed a NULL pointer dereference in send_acknowledge() (CVE-2023-46343).
    - CVE-2023-52340: Fixed ICMPv6 Packet Too Big packets force a DoS of the Linux kernel by forcing
    100% CPU (bsc#1219295).
    - CVE-2023-52429: Fixed potential DoS in dm_table_create in drivers/md/dm-table.c (bsc#1219827).
    - CVE-2023-52443: Fixed crash when parsed profile name is empty  (bsc#1220240).
    - CVE-2023-52445: Fixed use after free on context disconnection (bsc#1220241).
    - CVE-2023-52449: Fixed gluebi NULL pointer dereference caused by ftl notifier  (bsc#1220238).
    - CVE-2023-52451: Fixed access beyond end of drmem array  (bsc#1220250).
    - CVE-2023-52464: Fixed possible out-of-bounds string access (bsc#1220330)
    - CVE-2023-52475: Fixed use-after-free in powermate_config_complete (bsc#1220649)
    - CVE-2023-52478: Fixed kernel crash on receiver USB disconnect (bsc#1220796)
    - CVE-2023-52482: Fixed a bug by adding SRSO mitigation for Hygon processors (bsc#1220735).
    - CVE-2023-52502: Fixed a race condition in nfc_llcp_sock_get() and nfc_llcp_sock_get_sn() (bsc#1220831).
    - CVE-2023-52530: Fixed a potential key use-after-free in wifi mac80211 (bsc#1220930).
    - CVE-2023-52531: Fixed a memory corruption issue in iwlwifi (bsc#1220931).
    - CVE-2023-52532: Fixed a bug in TX CQE error handling (bsc#1220932).
    - CVE-2023-52574: Fixed a bug by hiding new member header_ops (bsc#1220870).
    - CVE-2023-52597: Fixed a setting of fpc register in KVM (bsc#1221040).
    - CVE-2023-52605: Fixed a NULL pointer dereference check (bsc#1221039)
    - CVE-2024-0607: Fixed 64-bit load issue in  nft_byteorder_eval() (bsc#1218915).
    - CVE-2024-1151: Fixed unlimited number of recursions from action  sets (bsc#1219835).
    - CVE-2024-23849: Fixed array-index-out-of-bounds in rds_cmsg_recv  (bsc#1219127).
    - CVE-2024-23851: Fixed crash in copy_params in drivers/md/dm-ioctl.c (bsc#1219146).
    - CVE-2024-26585: Fixed race between tx work scheduling and socket close  (bsc#1220187).
    - CVE-2024-26595: Fixed NULL pointer dereference in  error path (bsc#1220344).
    - CVE-2024-26600: Fixed NULL pointer dereference for SRP in phy-omap-usb2 (bsc#1220340).
    - CVE-2024-26622: Fixed UAF write bug in tomoyo_write_control() (bsc#1220825).


Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1050549");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186484");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200599");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212514");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213456");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218450");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218527");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218915");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219127");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219146");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219295");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219653");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219827");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219835");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220187");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220238");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220240");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220241");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220250");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220330");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220340");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220344");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220409");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220421");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220436");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220444");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220459");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220468");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220482");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220526");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220570");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220575");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220599");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220607");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220613");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220638");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220641");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220649");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220700");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220735");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220767");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220796");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220825");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220831");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220845");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220860");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220861");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220863");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220870");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220930");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220931");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220932");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220957");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221039");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221040");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221287");
  # https://lists.suse.com/pipermail/sle-security-updates/2024-March/018185.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ca852908");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-25162");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-36777");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-36784");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46906");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46915");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46921");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46924");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46929");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46932");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46953");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46974");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46991");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46992");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47013");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47054");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47076");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47077");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47078");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48627");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-28746");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-35827");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-46343");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52340");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52429");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52443");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52445");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52449");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52451");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52464");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52475");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52478");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52482");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52502");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52530");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52531");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52532");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52574");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52597");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52605");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-0607");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-1151");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-23849");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-23851");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26585");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26595");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26600");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26622");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-26622");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/03/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/03/23");

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
    {'reference':'cluster-md-kmp-rt-4.12.14-10.171.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Linux-Enterprise-RT-release-12.5']},
    {'reference':'dlm-kmp-rt-4.12.14-10.171.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Linux-Enterprise-RT-release-12.5']},
    {'reference':'gfs2-kmp-rt-4.12.14-10.171.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Linux-Enterprise-RT-release-12.5']},
    {'reference':'kernel-devel-rt-4.12.14-10.171.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Linux-Enterprise-RT-release-12.5']},
    {'reference':'kernel-rt-4.12.14-10.171.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Linux-Enterprise-RT-release-12.5']},
    {'reference':'kernel-rt-base-4.12.14-10.171.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Linux-Enterprise-RT-release-12.5']},
    {'reference':'kernel-rt-devel-4.12.14-10.171.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Linux-Enterprise-RT-release-12.5']},
    {'reference':'kernel-rt_debug-4.12.14-10.171.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Linux-Enterprise-RT-release-12.5']},
    {'reference':'kernel-rt_debug-devel-4.12.14-10.171.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Linux-Enterprise-RT-release-12.5']},
    {'reference':'kernel-source-rt-4.12.14-10.171.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Linux-Enterprise-RT-release-12.5']},
    {'reference':'kernel-syms-rt-4.12.14-10.171.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Linux-Enterprise-RT-release-12.5']},
    {'reference':'ocfs2-kmp-rt-4.12.14-10.171.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Linux-Enterprise-RT-release-12.5']}
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
