#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2024:1641-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(197051);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/27");

  script_cve_id(
    "CVE-2021-47047",
    "CVE-2021-47181",
    "CVE-2021-47182",
    "CVE-2021-47183",
    "CVE-2021-47184",
    "CVE-2021-47185",
    "CVE-2021-47187",
    "CVE-2021-47188",
    "CVE-2021-47189",
    "CVE-2021-47191",
    "CVE-2021-47192",
    "CVE-2021-47193",
    "CVE-2021-47194",
    "CVE-2021-47195",
    "CVE-2021-47196",
    "CVE-2021-47197",
    "CVE-2021-47198",
    "CVE-2021-47199",
    "CVE-2021-47200",
    "CVE-2021-47201",
    "CVE-2021-47202",
    "CVE-2021-47203",
    "CVE-2021-47204",
    "CVE-2021-47205",
    "CVE-2021-47206",
    "CVE-2021-47207",
    "CVE-2021-47209",
    "CVE-2021-47210",
    "CVE-2021-47211",
    "CVE-2021-47212",
    "CVE-2021-47215",
    "CVE-2021-47216",
    "CVE-2021-47217",
    "CVE-2021-47218",
    "CVE-2021-47219",
    "CVE-2022-48631",
    "CVE-2022-48637",
    "CVE-2022-48638",
    "CVE-2022-48647",
    "CVE-2022-48648",
    "CVE-2022-48650",
    "CVE-2022-48651",
    "CVE-2022-48653",
    "CVE-2022-48654",
    "CVE-2022-48655",
    "CVE-2022-48656",
    "CVE-2022-48657",
    "CVE-2022-48660",
    "CVE-2022-48662",
    "CVE-2022-48663",
    "CVE-2022-48667",
    "CVE-2022-48668",
    "CVE-2023-0160",
    "CVE-2023-4881",
    "CVE-2023-6270",
    "CVE-2023-7042",
    "CVE-2023-7192",
    "CVE-2023-52476",
    "CVE-2023-52500",
    "CVE-2023-52590",
    "CVE-2023-52591",
    "CVE-2023-52607",
    "CVE-2023-52616",
    "CVE-2023-52628",
    "CVE-2024-0841",
    "CVE-2024-22099",
    "CVE-2024-23307",
    "CVE-2024-23848",
    "CVE-2024-23850",
    "CVE-2024-25742",
    "CVE-2024-26601",
    "CVE-2024-26610",
    "CVE-2024-26614",
    "CVE-2024-26642",
    "CVE-2024-26687",
    "CVE-2024-26688",
    "CVE-2024-26689",
    "CVE-2024-26704",
    "CVE-2024-26727",
    "CVE-2024-26733",
    "CVE-2024-26739",
    "CVE-2024-26764",
    "CVE-2024-26766",
    "CVE-2024-26773",
    "CVE-2024-26792",
    "CVE-2024-26816",
    "CVE-2024-26898",
    "CVE-2024-26903",
    "CVE-2024-27043",
    "CVE-2024-27389"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2024:1641-1");

  script_name(english:"SUSE SLES15 Security Update : kernel (SUSE-SU-2024:1641-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 / SLES_SAP15 host has packages installed that are affected by multiple vulnerabilities as
referenced in the SUSE-SU-2024:1641-1 advisory.

    The SUSE Linux Enterprise 15 SP4 LTSS kernel was updated to receive various security bugfixes.


    The following security bugs were fixed:

    - CVE-2024-27389: Fixed pstore inode handling with d_invalidate() (bsc#1223705).
    - CVE-2024-27043: Fixed a use-after-free in edia/dvbdev in different places (bsc#1223824).
    - CVE-2024-26816: Ignore relocations in .notes section when building with CONFIG_XEN_PV=y (bsc#1222624).
    - CVE-2024-26773: Fixed ext4 block allocation from corrupted group in ext4_mb_try_best_found()
    (bsc#1222618).
    - CVE-2024-26766: Fixed SDMA off-by-one error in _pad_sdma_tx_descs() (bsc#1222726).
    - CVE-2024-26764: Fixed IOCB_AIO_RW check in fs/aio before the struct aio_kiocb conversion (bsc#1222721).
    - CVE-2024-26733: Fixed an overflow in arp_req_get() in arp (bsc#1222585).
    - CVE-2024-26727: Fixed assertion if a newly created btrfs subvolume already gets read (bsc#1222536).
    - CVE-2024-26704: Fixed a double-free of blocks due to wrong extents moved_len in ext4 (bsc#1222422).
    - CVE-2024-26689: Fixed a use-after-free in encode_cap_msg() (bsc#1222503).
    - CVE-2024-26687: Fixed xen/events close evtchn after mapping cleanup (bsc#1222435).
    - CVE-2024-26642: Fixed the set of anonymous timeout flag in netfilter nf_tables (bsc#1221830).
    - CVE-2024-26614: Fixed the initialization of accept_queue's spinlocks (bsc#1221293).
    - CVE-2024-26610: Fixed memory corruption in wifi/iwlwifi (bsc#1221299).
    - CVE-2024-26601: Fixed ext4 buddy bitmap corruption via fast commit replay (bsc#1220342).
    - CVE-2024-25742: Fixed insufficient validation during #VC instruction emulation in x86/sev (bsc#1221725).
    - CVE-2024-23850: Fixed double free of anonymous device after snapshot  creation failure (bsc#1219126).
    - CVE-2024-23307: Fixed Integer Overflow or Wraparound vulnerability in x86 and ARM md, raid, raid5
    modules (bsc#1219169).
    - CVE-2024-22099: Fixed a null-pointer-dereference in rfcomm_check_security (bsc#1219170).
    - CVE-2024-0841: Fixed a null pointer dereference in the hugetlbfs_fill_super function in hugetlbfs
    (HugeTLB pages) functionality (bsc#1219264).
    - CVE-2023-7192: Fixed a memory leak problem in ctnetlink_create_conntrack in
    net/netfilter/nf_conntrack_netlink.c (bsc#1218479).
    - CVE-2023-7042: Fixed a null-pointer-dereference in ath10k_wmi_tlv_op_pull_mgmt_tx_compl_ev()
    (bsc#1218336).
    - CVE-2023-6270: Fixed a use-after-free issue in aoecmd_cfg_pkts (bsc#1218562).
    - CVE-2023-52628: Fixed 4-byte stack OOB write in nftables (bsc#1222117).
    - CVE-2023-52616: Fixed unexpected pointer access in crypto/lib/mpi in mpi_ec_init (bsc#1221612).
    - CVE-2023-52607: Fixed NULL pointer dereference in pgtable_cache_add kasprintf() (bsc#1221061).
    - CVE-2023-52591: Fixed a possible reiserfs filesystem corruption via directory renaming (bsc#1221044).
    - CVE-2023-52590: Fixed a possible ocfs2 filesystem corruption via directory renaming (bsc#1221088).
    - CVE-2023-52500: Fixed information leaking when processing OPC_INB_SET_CONTROLLER_CONFIG command
    (bsc#1220883).
    - CVE-2023-52476: Fixed possible unhandled page fault via perf sampling NMI during vsyscall (bsc#1220703).
    - CVE-2023-4881: Fixed a out-of-bounds write flaw in the netfilter subsystem that could lead to potential
    information disclosure or a denial of service (bsc#1215221).
    - CVE-2023-0160: Fixed deadlock flaw in BPF that could allow a local user to potentially crash the system
    (bsc#1209657).
    - CVE-2022-48662: Fixed a general protection fault (GPF) in i915_perf_open_ioctl (bsc#1223505).
    - CVE-2022-48651: Fixed an out-of-bound bug in ipvlan caused by unset skb->mac_header (bsc#1223513).
    - CVE-2021-47202: Fixed NULL pointer dereferences in of_thermal_ functions (bsc#1222878)
    - CVE-2021-47195: Fixed use-after-free inside SPI via add_lock mutex (bsc#1222832).
    - CVE-2021-47189: Fixed denial of service due to memory ordering issues between normal and ordered work
    functions in btrfs (bsc#1222706).
    - CVE-2021-47185: Fixed a softlockup issue in flush_to_ldisc in tty tty_buffer (bsc#1222669).
    - CVE-2021-47183: Fixed a null pointer dereference during link down processing in scsi lpfc (bsc#1192145,
    bsc#1222664).
    - CVE-2021-47182: Fixed scsi_mode_sense() buffer length handling (bsc#1222662).
    - CVE-2021-47181: Fixed a null pointer dereference caused by calling platform_get_resource()
    (bsc#1222660).


Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192145");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209657");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215221");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1216223");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218336");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218479");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218562");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219104");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219126");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219169");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219170");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219264");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220342");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220703");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220761");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220883");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221044");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221061");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221088");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221293");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221299");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221612");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221725");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221830");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222117");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222422");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222430");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222435");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222482");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222503");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222536");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222559");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222585");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222618");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222624");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222660");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222662");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222664");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222666");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222669");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222671");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222703");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222704");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222706");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222709");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222721");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222726");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222773");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222776");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222785");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222787");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222790");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222791");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222792");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222796");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222824");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222829");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222832");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222836");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222838");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222866");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222867");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222869");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222876");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222878");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222879");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222881");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222883");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222888");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222894");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222901");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223016");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223187");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223380");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223474");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223475");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223477");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223479");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223482");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223484");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223487");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223503");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223505");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223509");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223513");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223516");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223517");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223518");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223519");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223522");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223523");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223705");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223824");
  script_set_attribute(attribute:"see_also", value:"https://lists.suse.com/pipermail/sle-updates/2024-May/035266.html");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47047");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47181");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47182");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47183");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47184");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47185");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47187");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47188");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47189");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47191");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47192");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47193");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47194");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47195");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47196");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47197");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47198");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47199");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47200");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47201");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47202");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47203");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47204");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47205");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47206");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47207");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47209");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47210");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47211");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47212");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47215");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47216");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47217");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47218");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47219");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48631");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48637");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48638");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48647");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48648");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48650");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48651");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48653");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48654");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48655");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48656");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48657");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48660");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48662");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48663");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48667");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48668");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-0160");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-4881");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52476");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52500");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52590");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52591");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52607");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52616");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52628");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-6270");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-7042");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-7192");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-0841");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-22099");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-23307");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-23848");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-23850");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-25742");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26601");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26610");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26614");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26642");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26687");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26688");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26689");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26704");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26727");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26733");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26739");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26764");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26766");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26773");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26792");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26816");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26898");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26903");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27043");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27389");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-27043");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/15");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-5_14_21-150400_24_119-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-obs-build");
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
if (! preg(pattern:"^(SLES15|SLES_SAP15)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15 / SLES_SAP15', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(4)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP4", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP15" && (! preg(pattern:"^(4)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP15 SP4", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'kernel-default-5.14.21-150400.24.119.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'kernel-default-base-5.14.21-150400.24.119.1.150400.24.56.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'kernel-default-devel-5.14.21-150400.24.119.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'kernel-devel-5.14.21-150400.24.119.1', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'kernel-macros-5.14.21-150400.24.119.1', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'kernel-obs-build-5.14.21-150400.24.119.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'kernel-source-5.14.21-150400.24.119.1', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'kernel-syms-5.14.21-150400.24.119.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'reiserfs-kmp-default-5.14.21-150400.24.119.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'kernel-64kb-5.14.21-150400.24.119.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'kernel-64kb-devel-5.14.21-150400.24.119.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'kernel-default-5.14.21-150400.24.119.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'kernel-default-5.14.21-150400.24.119.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4', 'SUSE-Manager-Proxy-release-4.3']},
    {'reference':'kernel-default-base-5.14.21-150400.24.119.1.150400.24.56.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'kernel-default-base-5.14.21-150400.24.119.1.150400.24.56.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3']},
    {'reference':'kernel-default-devel-5.14.21-150400.24.119.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'kernel-default-devel-5.14.21-150400.24.119.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4', 'SUSE-Manager-Proxy-release-4.3']},
    {'reference':'kernel-devel-5.14.21-150400.24.119.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3']},
    {'reference':'kernel-macros-5.14.21-150400.24.119.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3']},
    {'reference':'kernel-obs-build-5.14.21-150400.24.119.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'kernel-obs-build-5.14.21-150400.24.119.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'kernel-source-5.14.21-150400.24.119.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3']},
    {'reference':'kernel-syms-5.14.21-150400.24.119.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'kernel-syms-5.14.21-150400.24.119.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4', 'SUSE-Manager-Proxy-release-4.3']},
    {'reference':'reiserfs-kmp-default-5.14.21-150400.24.119.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'reiserfs-kmp-default-5.14.21-150400.24.119.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'kernel-64kb-5.14.21-150400.24.119.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4', 'sles-ltss-release-15.4']},
    {'reference':'kernel-64kb-devel-5.14.21-150400.24.119.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4', 'sles-ltss-release-15.4']},
    {'reference':'kernel-default-5.14.21-150400.24.119.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'kernel-default-5.14.21-150400.24.119.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'kernel-default-base-5.14.21-150400.24.119.1.150400.24.56.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4', 'sles-ltss-release-15.4']},
    {'reference':'kernel-default-base-5.14.21-150400.24.119.1.150400.24.56.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4', 'sles-ltss-release-15.4']},
    {'reference':'kernel-default-devel-5.14.21-150400.24.119.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'kernel-default-devel-5.14.21-150400.24.119.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'kernel-devel-5.14.21-150400.24.119.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4', 'sles-ltss-release-15.4']},
    {'reference':'kernel-macros-5.14.21-150400.24.119.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4', 'sles-ltss-release-15.4']},
    {'reference':'kernel-obs-build-5.14.21-150400.24.119.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'kernel-obs-build-5.14.21-150400.24.119.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'kernel-source-5.14.21-150400.24.119.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4', 'sles-ltss-release-15.4']},
    {'reference':'kernel-syms-5.14.21-150400.24.119.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'kernel-syms-5.14.21-150400.24.119.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'reiserfs-kmp-default-5.14.21-150400.24.119.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'reiserfs-kmp-default-5.14.21-150400.24.119.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'kernel-default-5.14.21-150400.24.119.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'kernel-default-devel-5.14.21-150400.24.119.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'kernel-syms-5.14.21-150400.24.119.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'kernel-zfcpdump-5.14.21-150400.24.119.1', 'sp':'4', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'cluster-md-kmp-default-5.14.21-150400.24.119.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.4']},
    {'reference':'dlm-kmp-default-5.14.21-150400.24.119.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.4']},
    {'reference':'gfs2-kmp-default-5.14.21-150400.24.119.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.4']},
    {'reference':'ocfs2-kmp-default-5.14.21-150400.24.119.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.4']},
    {'reference':'kernel-default-livepatch-5.14.21-150400.24.119.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.4']},
    {'reference':'kernel-default-livepatch-devel-5.14.21-150400.24.119.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.4']},
    {'reference':'kernel-livepatch-5_14_21-150400_24_119-default-1-150400.9.3.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.4']},
    {'reference':'kernel-default-5.14.21-150400.24.119.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.4']},
    {'reference':'kernel-default-devel-5.14.21-150400.24.119.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.4']},
    {'reference':'kernel-obs-build-5.14.21-150400.24.119.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.4']},
    {'reference':'kernel-syms-5.14.21-150400.24.119.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.4']},
    {'reference':'kernel-zfcpdump-5.14.21-150400.24.119.1', 'sp':'4', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.4']},
    {'reference':'reiserfs-kmp-default-5.14.21-150400.24.119.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.4']}
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
