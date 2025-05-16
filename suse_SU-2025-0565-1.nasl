#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2025:0565-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(216454);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/09");

  script_cve_id(
    "CVE-2021-47222",
    "CVE-2021-47223",
    "CVE-2024-26644",
    "CVE-2024-47809",
    "CVE-2024-48881",
    "CVE-2024-49948",
    "CVE-2024-50142",
    "CVE-2024-52332",
    "CVE-2024-53155",
    "CVE-2024-53185",
    "CVE-2024-53197",
    "CVE-2024-53227",
    "CVE-2024-55916",
    "CVE-2024-56369",
    "CVE-2024-56532",
    "CVE-2024-56533",
    "CVE-2024-56539",
    "CVE-2024-56574",
    "CVE-2024-56593",
    "CVE-2024-56594",
    "CVE-2024-56600",
    "CVE-2024-56601",
    "CVE-2024-56615",
    "CVE-2024-56623",
    "CVE-2024-56630",
    "CVE-2024-56637",
    "CVE-2024-56641",
    "CVE-2024-56643",
    "CVE-2024-56650",
    "CVE-2024-56661",
    "CVE-2024-56662",
    "CVE-2024-56681",
    "CVE-2024-56700",
    "CVE-2024-56722",
    "CVE-2024-56739",
    "CVE-2024-56747",
    "CVE-2024-56748",
    "CVE-2024-56759",
    "CVE-2024-56763",
    "CVE-2024-56769",
    "CVE-2024-57884",
    "CVE-2024-57890",
    "CVE-2024-57896",
    "CVE-2024-57899",
    "CVE-2024-57903",
    "CVE-2024-57922",
    "CVE-2024-57929",
    "CVE-2024-57931",
    "CVE-2024-57932",
    "CVE-2024-57938",
    "CVE-2025-21653",
    "CVE-2025-21664",
    "CVE-2025-21678",
    "CVE-2025-21682"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2025:0565-1");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2025/04/30");

  script_name(english:"SUSE SLES12 Security Update : kernel (SUSE-SU-2025:0565-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES12 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SUSE-SU-2025:0565-1 advisory.

    The SUSE Linux Enterprise 12 SP5 kernel was updated to receive various security bugfixes.


    The following security bugs were fixed:

    - CVE-2021-47222: net: bridge: fix vlan tunnel dst refcnt when egressing (bsc#1224857).
    - CVE-2021-47223: net: bridge: fix vlan tunnel dst null pointer dereference (bsc#1224856).
    - CVE-2024-26644: btrfs: do not abort filesystem when attempting to snapshot deleted subvolume
    (bsc#1222072).
    - CVE-2024-47809: dlm: fix possible lkb_resource null dereference (bsc#1235714).
    - CVE-2024-48881: bcache: revert replacing IS_ERR_OR_NULL with IS_ERR again (bsc#1235727).
    - CVE-2024-49948: net: add more sanity checks to qdisc_pkt_len_init() (bsc#1232161).
    - CVE-2024-50142: xfrm: validate new SA's prefixlen using SA family when sel.family is unset
    (bsc#1233028).
    - CVE-2024-52332: igb: Fix potential invalid memory access in igb_init_module() (bsc#1235700).
    - CVE-2024-53155: ocfs2: fix uninitialized value in ocfs2_file_read_iter() (bsc#1234855).
    - CVE-2024-53185: smb: client: fix NULL ptr deref in crypto_aead_setkey() (bsc#1234901).
    - CVE-2024-53197: ALSA: usb-audio: Fix potential out-of-bound accesses for Extigy and Mbox devices
    (bsc#1235464).
    - CVE-2024-53227: scsi: bfa: Fix use-after-free in bfad_im_module_exit() (bsc#1235011).
    - CVE-2024-55916: Drivers: hv: util: Avoid accessing a ringbuffer not initialized yet (bsc#1235747).
    - CVE-2024-56369: drm/modes: Avoid divide by zero harder in drm_mode_vrefresh() (bsc#1235750).
    - CVE-2024-56532: ALSA: us122l: Use snd_card_free_when_closed() at disconnection (bsc#1235059).
    - CVE-2024-56533: ALSA: usx2y: Use snd_card_free_when_closed() at disconnection (bsc#1235053).
    - CVE-2024-56539: wifi: mwifiex: Fix memcpy() field-spanning write warning in mwifiex_config_scan()
    (bsc#1234963).
    - CVE-2024-56574: media: ts2020: fix null-ptr-deref in ts2020_probe() (bsc#1235040).
    - CVE-2024-56593: wifi: brcmfmac: Fix oops due to NULL pointer dereference in brcmf_sdiod_sglist_rw()
    (bsc#1235252).
    - CVE-2024-56594: drm/amdgpu: set the right AMDGPU sg segment limitation (bsc#1235413).
    - CVE-2024-56600: net: inet6: do not leave a dangling sk pointer in inet6_create() (bsc#1235217).
    - CVE-2024-56601: net: inet: do not leave a dangling sk pointer in inet_create() (bsc#1235230).
    - CVE-2024-56615: bpf: fix OOB devmap writes when deleting elements (bsc#1235426).
    - CVE-2024-56623: scsi: qla2xxx: Fix use after free on unload (bsc#1235466).
    - CVE-2024-56630: ocfs2: free inode when ocfs2_get_init_inode() fails (bsc#1235479).
    - CVE-2024-56637: netfilter: ipset: Hold module reference while requesting a module (bsc#1235523).
    - CVE-2024-56641: net/smc: initialize close_work early to avoid warning (bsc#1235526).
    - CVE-2024-56643: dccp: Fix memory leak in dccp_feat_change_recv (bsc#1235132).
    - CVE-2024-56650: netfilter: x_tables: fix LED ID check in led_tg_check() (bsc#1235430).
    - CVE-2024-56662: acpi: nfit: vmalloc-out-of-bounds Read in acpi_nfit_ctl (bsc#1235533).
    - CVE-2024-56681: crypto: bcm - add error check in the ahash_hmac_init function (bsc#1235557).
    - CVE-2024-56700: media: wl128x: Fix atomicity violation in fmc_send_cmd() (bsc#1235500).
    - CVE-2024-56722: RDMA/hns: Fix cpu stuck caused by printings during reset (bsc#1235570).
    - CVE-2024-56739: rtc: check if __rtc_read_time was successful in rtc_timer_do_work() (bsc#1235611).
    - CVE-2024-56747: scsi: qedi: Fix a possible memory leak in qedi_alloc_and_init_sb() (bsc#1234934).
    - CVE-2024-56748: scsi: qedf: Fix a possible memory leak in qedf_alloc_and_init_sb() (bsc#1235627).
    - CVE-2024-56759: btrfs: fix use-after-free when COWing tree bock and tracing is enabled (bsc#1235645).
    - CVE-2024-56763: tracing: Prevent bad count for tracing_cpumask_write (bsc#1235638).
    - CVE-2024-56769: media: dvb-frontends: dib3000mb: fix uninit-value in dib3000_write_reg (bsc#1235155).
    - CVE-2024-57884: mm: vmscan: account for free pages to prevent infinite Loop in throttle_direct_reclaim()
    (bsc#1235948).
    - CVE-2024-57890: RDMA/uverbs: Prevent integer overflow issue (bsc#1235919).
    - CVE-2024-57896: btrfs: flush delalloc workers queue before stopping cleaner kthread during unmount
    (bsc#1235965).
    - CVE-2024-57899: wifi: mac80211: fix mbss changed flags corruption on 32 bit systems (bsc#1235924).
    - CVE-2024-57903: net: restrict SO_REUSEPORT to inet sockets (bsc#1235967).
    - CVE-2024-57922: drm/amd/display: Add check for granularity in dml ceil/floor helpers (bsc#1236080).
    - CVE-2024-57929: dm array: fix releasing a faulty array block twice in dm_array_cursor_end (bsc#1236096).
    - CVE-2024-57931: selinux: ignore unknown extended permissions (bsc#1236192).
    - CVE-2024-57932: gve: guard XDP xmit NDO on existence of xdp queues (bsc#1236190).
    - CVE-2024-57938: net/sctp: Prevent autoclose integer overflow in sctp_association_init() (bsc#1236182).
    - CVE-2025-21653: net_sched: cls_flow: validate TCA_FLOW_RSHIFT attribute (bsc#1236161).
    - CVE-2025-21664: dm thin: make get_first_thin use rcu-safe list first function (bsc#1236262).
    - CVE-2025-21678: gtp: Destroy device along with udp socket's netns dismantle (bsc#1236698).
    - CVE-2025-21682: eth: bnxt: always recalculate features after XDP clearing, fix null-deref (bsc#1236703).


Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221282");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222072");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222803");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224856");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224857");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232161");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233028");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234855");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234901");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234931");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234934");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234963");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235011");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235040");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235053");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235059");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235132");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235155");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235217");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235230");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235252");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235413");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235426");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235430");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235433");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235464");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235466");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235479");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235500");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235523");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235526");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235533");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235557");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235570");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235611");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235627");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235638");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235645");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235700");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235714");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235727");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235747");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235750");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235919");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235924");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235948");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235965");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235967");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236080");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236096");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236161");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236182");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236190");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236192");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236262");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236698");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236703");
  # https://lists.suse.com/pipermail/sle-security-updates/2025-February/020360.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ee0d8a43");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47222");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47223");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26644");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47809");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-48881");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49948");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50142");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-52332");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53155");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53185");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53197");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53227");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-55916");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56369");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56532");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56533");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56539");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56574");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56593");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56594");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56600");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56601");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56615");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56623");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56630");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56637");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56641");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56643");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56650");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56661");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56662");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56681");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56700");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56722");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56739");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56747");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56748");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56759");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56763");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56769");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-57884");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-57890");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-57896");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-57899");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-57903");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-57922");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-57929");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-57931");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-57932");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-57938");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21653");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21664");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21678");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21682");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-57896");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/02/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cluster-md-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dlm-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gfs2-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-kgraft");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-kgraft-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-man");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_12_14-122_247-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ocfs2-kmp-default");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
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
    {'reference':'kernel-default-kgraft-4.12.14-122.247.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-live-patching-release-12.5']},
    {'reference':'kernel-default-kgraft-devel-4.12.14-122.247.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-live-patching-release-12.5']},
    {'reference':'kgraft-patch-4_12_14-122_247-default-1-8.3.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-live-patching-release-12.5']},
    {'reference':'cluster-md-kmp-default-4.12.14-122.247.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-extended-security-release-12.5']},
    {'reference':'dlm-kmp-default-4.12.14-122.247.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-extended-security-release-12.5']},
    {'reference':'gfs2-kmp-default-4.12.14-122.247.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-extended-security-release-12.5']},
    {'reference':'kernel-default-4.12.14-122.247.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-extended-security-release-12.5']},
    {'reference':'kernel-default-base-4.12.14-122.247.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-extended-security-release-12.5']},
    {'reference':'kernel-default-devel-4.12.14-122.247.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-extended-security-release-12.5']},
    {'reference':'kernel-devel-4.12.14-122.247.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-extended-security-release-12.5']},
    {'reference':'kernel-macros-4.12.14-122.247.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-extended-security-release-12.5']},
    {'reference':'kernel-source-4.12.14-122.247.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-extended-security-release-12.5']},
    {'reference':'kernel-syms-4.12.14-122.247.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-extended-security-release-12.5']},
    {'reference':'ocfs2-kmp-default-4.12.14-122.247.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-extended-security-release-12.5']},
    {'reference':'cluster-md-kmp-default-4.12.14-122.247.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'dlm-kmp-default-4.12.14-122.247.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'gfs2-kmp-default-4.12.14-122.247.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'kernel-default-4.12.14-122.247.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'kernel-default-base-4.12.14-122.247.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'kernel-default-devel-4.12.14-122.247.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'kernel-default-man-4.12.14-122.247.1', 'sp':'5', 'cpu':'s390x', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'kernel-devel-4.12.14-122.247.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'kernel-macros-4.12.14-122.247.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'kernel-source-4.12.14-122.247.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'kernel-syms-4.12.14-122.247.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'ocfs2-kmp-default-4.12.14-122.247.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']}
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
