#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2024:1644-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(197056);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/27");

  script_cve_id(
    "CVE-2021-47047",
    "CVE-2021-47184",
    "CVE-2021-47185",
    "CVE-2021-47187",
    "CVE-2021-47188",
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
    "CVE-2021-47214",
    "CVE-2021-47215",
    "CVE-2021-47216",
    "CVE-2021-47217",
    "CVE-2021-47218",
    "CVE-2021-47219",
    "CVE-2022-48631",
    "CVE-2022-48632",
    "CVE-2022-48634",
    "CVE-2022-48636",
    "CVE-2022-48637",
    "CVE-2022-48638",
    "CVE-2022-48639",
    "CVE-2022-48640",
    "CVE-2022-48642",
    "CVE-2022-48644",
    "CVE-2022-48646",
    "CVE-2022-48647",
    "CVE-2022-48648",
    "CVE-2022-48650",
    "CVE-2022-48651",
    "CVE-2022-48652",
    "CVE-2022-48653",
    "CVE-2022-48654",
    "CVE-2022-48655",
    "CVE-2022-48656",
    "CVE-2022-48657",
    "CVE-2022-48658",
    "CVE-2022-48659",
    "CVE-2022-48660",
    "CVE-2022-48662",
    "CVE-2022-48663",
    "CVE-2022-48667",
    "CVE-2022-48668",
    "CVE-2022-48671",
    "CVE-2022-48672",
    "CVE-2022-48673",
    "CVE-2022-48675",
    "CVE-2022-48686",
    "CVE-2022-48687",
    "CVE-2022-48688",
    "CVE-2022-48690",
    "CVE-2022-48692",
    "CVE-2022-48693",
    "CVE-2022-48694",
    "CVE-2022-48695",
    "CVE-2022-48697",
    "CVE-2022-48698",
    "CVE-2022-48699",
    "CVE-2022-48700",
    "CVE-2022-48701",
    "CVE-2022-48702",
    "CVE-2022-48703",
    "CVE-2022-48704",
    "CVE-2023-2860",
    "CVE-2023-6270",
    "CVE-2023-52585",
    "CVE-2023-52589",
    "CVE-2023-52590",
    "CVE-2023-52591",
    "CVE-2023-52593",
    "CVE-2023-52614",
    "CVE-2023-52616",
    "CVE-2023-52620",
    "CVE-2023-52635",
    "CVE-2023-52645",
    "CVE-2023-52646",
    "CVE-2023-52652",
    "CVE-2024-0639",
    "CVE-2024-0841",
    "CVE-2024-2201",
    "CVE-2024-22099",
    "CVE-2024-23307",
    "CVE-2024-23848",
    "CVE-2024-23850",
    "CVE-2024-26601",
    "CVE-2024-26610",
    "CVE-2024-26656",
    "CVE-2024-26671",
    "CVE-2024-26673",
    "CVE-2024-26675",
    "CVE-2024-26679",
    "CVE-2024-26687",
    "CVE-2024-26688",
    "CVE-2024-26700",
    "CVE-2024-26702",
    "CVE-2024-26733",
    "CVE-2024-26739",
    "CVE-2024-26764",
    "CVE-2024-26766",
    "CVE-2024-26772",
    "CVE-2024-26773",
    "CVE-2024-26783",
    "CVE-2024-26791",
    "CVE-2024-26792",
    "CVE-2024-26816",
    "CVE-2024-26817",
    "CVE-2024-26820",
    "CVE-2024-26825",
    "CVE-2024-26830",
    "CVE-2024-26833",
    "CVE-2024-26836",
    "CVE-2024-26840",
    "CVE-2024-26843",
    "CVE-2024-26852",
    "CVE-2024-26853",
    "CVE-2024-26855",
    "CVE-2024-26856",
    "CVE-2024-26857",
    "CVE-2024-26861",
    "CVE-2024-26862",
    "CVE-2024-26866",
    "CVE-2024-26872",
    "CVE-2024-26875",
    "CVE-2024-26876",
    "CVE-2024-26877",
    "CVE-2024-26878",
    "CVE-2024-26879",
    "CVE-2024-26881",
    "CVE-2024-26882",
    "CVE-2024-26883",
    "CVE-2024-26884",
    "CVE-2024-26885",
    "CVE-2024-26891",
    "CVE-2024-26893",
    "CVE-2024-26895",
    "CVE-2024-26896",
    "CVE-2024-26897",
    "CVE-2024-26898",
    "CVE-2024-26901",
    "CVE-2024-26903",
    "CVE-2024-26915",
    "CVE-2024-26917",
    "CVE-2024-26927",
    "CVE-2024-26933",
    "CVE-2024-26939",
    "CVE-2024-26948",
    "CVE-2024-26950",
    "CVE-2024-26951",
    "CVE-2024-26955",
    "CVE-2024-26956",
    "CVE-2024-26960",
    "CVE-2024-26965",
    "CVE-2024-26966",
    "CVE-2024-26969",
    "CVE-2024-26970",
    "CVE-2024-26972",
    "CVE-2024-26979",
    "CVE-2024-26981",
    "CVE-2024-26982",
    "CVE-2024-26993",
    "CVE-2024-27013",
    "CVE-2024-27014",
    "CVE-2024-27030",
    "CVE-2024-27038",
    "CVE-2024-27039",
    "CVE-2024-27041",
    "CVE-2024-27042",
    "CVE-2024-27043",
    "CVE-2024-27046",
    "CVE-2024-27056",
    "CVE-2024-27059",
    "CVE-2024-27062",
    "CVE-2024-27389"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2024:1644-1");

  script_name(english:"SUSE SLES15 / openSUSE 15 Security Update : kernel (SUSE-SU-2024:1644-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 / SLES_SAP15 / openSUSE 15 host has packages installed that are affected by multiple
vulnerabilities as referenced in the SUSE-SU-2024:1644-1 advisory.

    The SUSE Linux Enterprise 15 SP5 Azure kernel was updated to receive various security bugfixes.


    The following security bugs were fixed:

    - CVE-2024-27389: Fixed pstore inode handling with d_invalidate() (bsc#1223705).
    - CVE-2024-27062: Fixed nouveau lock inside client object tree (bsc#1223834).
    - CVE-2024-27056: Fixed wifi/iwlwifi/mvm to ensure offloading TID queue exists (bsc#1223822).
    - CVE-2024-27046: Fixed nfp/flower handling acti_netdevs allocation failure (bsc#1223827).
    - CVE-2024-27043: Fixed a use-after-free in edia/dvbdev in different places (bsc#1223824).
    - CVE-2024-27042: Fixed drm/amdgpu for potential out-of-bounds access in amdgpu_discovery_reg_base_init()
    (bsc#1223823).
    - CVE-2024-27041: Fixed drm/amd/display NULL checks for adev->dm.dc in amdgpu_dm_fini() (bsc#1223714).
    - CVE-2024-27039: Fixed clk/hisilicon/hi3559a an erroneous devm_kfree() (bsc#1223821).
    - CVE-2024-27038: Fixed clk_core_get NULL pointer dereference (bsc#1223816).
    - CVE-2024-27030: Fixed octeontx2-af to use separate handlers for interrupts (bsc#1223790).
    - CVE-2024-27014: Fixed net/mlx5e to prevent deadlock while disabling aRFS (bsc#1223735).
    - CVE-2024-27013: Fixed tun limit printing rate when illegal packet received by tun device (bsc#1223745).
    - CVE-2024-26993: Fixed fs/sysfs reference leak in sysfs_break_active_protection() (bsc#1223693).
    - CVE-2024-26982: Fixed Squashfs inode number check not to be an invalid value of zero (bsc#1223634).
    - CVE-2024-26970: Fixed clk/qcom/gcc-ipq6018 termination of frequency table arrays (bsc#1223644).
    - CVE-2024-26969: Fixed clk/qcom/gcc-ipq8074 termination of frequency table arrays (bsc#1223645).
    - CVE-2024-26966: Fixed clk/qcom/mmcc-apq8084 termination of frequency table arrays (bsc#1223646).
    - CVE-2024-26965: Fixed clk/qcom/mmcc-msm8974 termination of frequency table arrays (bsc#1223648).
    - CVE-2024-26960: Fixed mm/swap race between free_swap_and_cache() and swapoff() (bsc#1223655).
    - CVE-2024-26951: Fixed wireguard/netlink check for dangling peer via is_dead instead of empty list
    (bsc#1223660).
    - CVE-2024-26950: Fixed wireguard/netlink to access device through ctx instead of peer (bsc#1223661).
    - CVE-2024-26948: Fixed drm/amd/display by adding dc_state NULL check in dc_state_release (bsc#1223664).
    - CVE-2024-26939: Fixed drm/i915/vma UAF on destroy against retire race (bsc#1223679).
    - CVE-2024-26927: Fixed ASoC/SOF bounds checking to firmware data Smatch (bsc#1223525).
    - CVE-2024-26915: Fixed drm/amdgpu reset IH OVERFLOW_CLEAR bit (bsc#1223207).
    - CVE-2024-26901: Fixed do_sys_name_to_handle() to use kzalloc() to prevent kernel-infoleak (bsc#1223198).
    - CVE-2024-26898: Fixed aoe potential use-after-free problem in aoecmd_cfg_pkts (bsc#1223016).
    - CVE-2024-26896: Fixed wifi/wfx memory leak when starting AP (bsc#1223042).
    - CVE-2024-26893: Fixed firmware/arm_scmi for possible double free in SMC transport cleanup path
    (bsc#1223196).
    - CVE-2024-26885: Fixed bpf DEVMAP_HASH overflow check on 32-bit arches (bsc#1223190).
    - CVE-2024-26884: Fixed bpf hashtab overflow check on 32-bit arches (bsc#1223189).
    - CVE-2024-26883: Fixed bpf stackmap overflow check on 32-bit arches (bsc#1223035).
    - CVE-2024-26882: Fixed net/ip_tunnel to make sure to pull inner header in ip_tunnel_rcv() (bsc#1223034).
    - CVE-2024-26881: Fixed net/hns3 kernel crash when 1588 is received on HIP08 devices (bsc#1223041).
    - CVE-2024-26879: Fixed clk/meson by adding missing clocks to axg_clk_regmaps (bsc#1223066).
    - CVE-2024-26878: Fixed quota for potential NULL pointer dereference (bsc#1223060).
    - CVE-2024-26876: Fixed drm/bridge/adv7511 crash on irq during probe (bsc#1223119).
    - CVE-2024-26866: Fixed spi/spi-fsl-lpspi by removing redundant spi_controller_put call (bsc#1223024).
    - CVE-2024-26862: Fixed packet annotate data-races around ignore_outgoing (bsc#1223111).
    - CVE-2024-26861: Fixed wireguard/receive annotate data-race around receiving_counter.counter
    (bsc#1223076).
    - CVE-2024-26857: Fixed geneve to make sure to pull inner header in geneve_rx() (bsc#1223058).
    - CVE-2024-26856: Fixed use-after-free inside sparx5_del_mact_entry (bsc#1223052).
    - CVE-2024-26855: Fixed net/ice potential NULL pointer dereference in ice_bridge_setlink() (bsc#1223051).
    - CVE-2024-26853: Fixed igc returning frame twice in XDP_REDIRECT (bsc#1223061).
    - CVE-2024-26852: Fixed net/ipv6 to avoid possible UAF in ip6_route_mpath_notify() (bsc#1223057).
    - CVE-2024-26840: Fixed a memory leak in cachefiles_add_cache() (bsc#1222976).
    - CVE-2024-26836: Fixed platform/x86/think-lmi password opcode ordering for workstations (bsc#1222968).
    - CVE-2024-26830: Fixed i40e to not allow untrusted VF to remove administratively set MAC (bsc#1223012).
    - CVE-2024-26817: Fixed amdkfd to use calloc instead of kzalloc to avoid integer overflow (bsc#1222812).
    - CVE-2024-26816: Fixed relocations in .notes section when building with CONFIG_XEN_PV=y by ignoring them
    (bsc#1222624).
    - CVE-2024-26791: Fixed btrfs/dev-replace properly validate device names (bsc#1222793).
    - CVE-2024-26783: Fixed mm/vmscan bug when calling wakeup_kswapd() with a wrong zone index (bsc#1222615).
    - CVE-2024-26773: Fixed ext4 block allocation from corrupted group in ext4_mb_try_best_found()
    (bsc#1222618).
    - CVE-2024-26772: Fixed ext4 to avoid allocating blocks from corrupted group in ext4_mb_find_by_goal()
    (bsc#1222613).
    - CVE-2024-26766: Fixed SDMA off-by-one error in _pad_sdma_tx_descs() (bsc#1222726).
    - CVE-2024-26764: Fixed IOCB_AIO_RW check in fs/aio before the struct aio_kiocb conversion (bsc#1222721).
    - CVE-2024-26733: Fixed an overflow in arp_req_get() in arp (bsc#1222585).
    - CVE-2024-26700: Fixed drm/amd/display MST Null pointer dereference  for RV (bsc#1222870).
    - CVE-2024-26687: Fixed xen/events close evtchn after mapping cleanup (bsc#1222435).
    - CVE-2024-26679: Fixed inet read sk->sk_family once in inet_recv_error() (bsc#1222385).
    - CVE-2024-26675: Fixed ppp_async to limit MRU to 64K (bsc#1222379).
    - CVE-2024-26673: Fixed netfilter/nft_ct layer 3 and 4 protocol sanitization (bsc#1222368).
    - CVE-2024-26671: Fixed blk-mq IO hang from sbitmap wakeup race (bsc#1222357).
    - CVE-2024-26656: Fixed drm/amdgpu use-after-free bug (bsc#1222307).
    - CVE-2024-26610: Fixed memory corruption in wifi/iwlwifi (bsc#1221299).
    - CVE-2024-26601: Fixed ext4 buddy bitmap corruption via fast commit replay (bsc#1220342).
    - CVE-2024-23850: Fixed double free of anonymous device after snapshot  creation failure (bsc#1219126).
    - CVE-2024-23848: Fixed media/cec for possible use-after-free in cec_queue_msg_fh (bsc#1219104).
    - CVE-2024-23307: Fixed Integer Overflow or Wraparound vulnerability in x86 and ARM md, raid, raid5
    modules (bsc#1219169).
    - CVE-2024-22099: Fixed a null-pointer-dereference in rfcomm_check_security (bsc#1219170).
    - CVE-2024-2201: Fixed information leak in x86/BHI (bsc#1217339).
    - CVE-2024-0841: Fixed a null pointer dereference in the hugetlbfs_fill_super function in hugetlbfs
    (HugeTLB pages) functionality (bsc#1219264).
    - CVE-2024-0639: Fixed a denial-of-service vulnerability due to a deadlock found in sctp_auto_asconf_init
    in net/sctp/socket.c (bsc#1218917).
    - CVE-2023-6270: Fixed a use-after-free issue in aoecmd_cfg_pkts (bsc#1218562).
    - CVE-2023-52652: Fixed NTB for possible name leak in ntb_register_device() (bsc#1223686).
    - CVE-2023-52645: Fixed pmdomain/mediatek race conditions with genpd (bsc#1223033).
    - CVE-2023-52635: Fixed PM/devfreq to synchronize devfreq_monitor_[start/stop] (bsc#1222294).
    - CVE-2023-52620: Fixed netfilter/nf_tables to disallow timeout for anonymous sets never used from
    userspace (bsc#1221825).
    - CVE-2023-52616: Fixed unexpected pointer access in crypto/lib/mpi in mpi_ec_init (bsc#1221612).
    - CVE-2023-52614: Fixed PM/devfreq buffer overflow in trans_stat_show (bsc#1221617).
    - CVE-2023-52593: Fixed wifi/wfx possible NULL pointer dereference in wfx_set_mfp_ap() (bsc#1221042).
    - CVE-2023-52591: Fixed a possible reiserfs filesystem corruption via directory renaming (bsc#1221044).
    - CVE-2023-52590: Fixed a possible ocfs2 filesystem corruption via directory renaming (bsc#1221088).
    - CVE-2023-52589: Fixed media/rkisp1 IRQ disable race issue (bsc#1221084).
    - CVE-2023-52585: Fixed drm/amdgpu for possible NULL pointer dereference in
    amdgpu_ras_query_error_status_helper() (bsc#1221080).
    - CVE-2022-48662: Fixed a general protection fault (GPF) in i915_perf_open_ioctl (bsc#1223505).
    - CVE-2022-48659: Fixed mm/slub to return errno if kmalloc() fails (bsc#1223498).
    - CVE-2022-48658: Fixed mm/slub to avoid a problem in flush_cpu_slab()/__free_slab() task context
    (bsc#1223496).
    - CVE-2022-48651: Fixed an out-of-bound bug in ipvlan caused by unset skb->mac_header (bsc#1223513).
    - CVE-2022-48642: Fixed netfilter/nf_tables percpu memory leak at nf_tables_addchain() (bsc#1223478).
    - CVE-2022-48640: Fixed bonding for possible NULL pointer dereference in bond_rr_gen_slave_id
    (bsc#1223499).
    - CVE-2022-48631: Fixed a bug in ext4, when parsing extents where eh_entries == 0 and eh_depth > 0
    (bsc#1223475).
    - CVE-2021-47214: Fixed hugetlb/userfaultfd during restore reservation in hugetlb_mcopy_atomic_pte()
    (bsc#1222710).
    - CVE-2021-47211: Fixed a null pointer dereference on pointer cs_desc in usb-audio (bsc#1222869).
    - CVE-2021-47207: Fixed a null pointer dereference on pointer block in gus (bsc#1222790).
    - CVE-2021-47205: Unregistered clocks/resets when unbinding in sunxi-ng (bsc#1222888).
    - CVE-2021-47202: Fixed NULL pointer dereferences in of_thermal_ functions (bsc#1222878)
    - CVE-2021-47200: Fixed drm/prime for possible use-after-free in mmap within drm_gem_ttm_mmap() and
    drm_gem_ttm_mmap() (bsc#1222838).
    - CVE-2021-47195: Fixed use-after-free inside SPI via add_lock mutex (bsc#1222832).
    - CVE-2021-47185: Fixed a softlockup issue in flush_to_ldisc in tty tty_buffer (bsc#1222669).
    - CVE-2021-47184: Fixed NULL pointer dereference on VSI filter sync (bsc#1222666).


Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1141539");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190576");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192145");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192837");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193629");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196869");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200313");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201308");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201489");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203906");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203935");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204614");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207361");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211592");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213573");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217339");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217408");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218562");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218917");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219104");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219126");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219141");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219169");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219170");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219264");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220342");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220569");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220761");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221042");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221044");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221080");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221084");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221088");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221299");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221612");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221617");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221645");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221825");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222294");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222307");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222357");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222368");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222379");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222385");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222424");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222430");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222435");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222482");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222559");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222585");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222613");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222615");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222618");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222624");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222666");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222669");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222671");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222703");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222704");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222709");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222710");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222721");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222726");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222773");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222776");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222785");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222787");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222790");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222791");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222792");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222793");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222796");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222812");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222824");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222829");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222832");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222836");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222838");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222866");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222867");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222869");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222870");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222876");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222878");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222879");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222881");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222883");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222888");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222894");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222901");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222968");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222976");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223012");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223014");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223016");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223024");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223033");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223034");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223035");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223036");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223037");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223041");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223042");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223051");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223052");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223056");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223057");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223058");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223060");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223061");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223065");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223066");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223076");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223078");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223111");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223115");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223118");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223119");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223140");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223187");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223189");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223190");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223191");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223196");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223197");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223198");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223207");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223275");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223323");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223360");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223369");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223380");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223432");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223473");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223474");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223475");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223477");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223478");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223479");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223481");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223482");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223484");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223487");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223490");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223496");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223498");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223499");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223501");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223502");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223503");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223505");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223509");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223511");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223512");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223513");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223516");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223517");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223518");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223519");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223520");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223522");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223523");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223525");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223536");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223539");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223574");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223595");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223598");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223628");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223634");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223640");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223643");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223644");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223645");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223646");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223648");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223655");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223657");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223660");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223661");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223663");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223664");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223668");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223670");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223679");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223686");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223693");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223705");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223714");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223735");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223738");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223745");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223784");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223785");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223790");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223816");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223821");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223822");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223823");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223824");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223827");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223834");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223858");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223875");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223876");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223877");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223878");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223879");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223894");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223921");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223922");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223923");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223924");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223929");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223931");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223932");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223934");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223941");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223948");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223949");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223950");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223951");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223952");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223953");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223956");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223957");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223960");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223962");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223963");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223964");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223996");
  script_set_attribute(attribute:"see_also", value:"https://lists.suse.com/pipermail/sle-updates/2024-May/035263.html");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47047");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47184");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47185");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47187");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47188");
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
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47214");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47215");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47216");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47217");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47218");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47219");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48631");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48632");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48634");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48636");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48637");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48638");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48639");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48640");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48642");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48644");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48646");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48647");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48648");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48650");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48651");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48652");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48653");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48654");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48655");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48656");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48657");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48658");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48659");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48660");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48662");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48663");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48667");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48668");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48671");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48672");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48673");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48675");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48686");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48687");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48688");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48690");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48692");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48693");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48694");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48695");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48697");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48698");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48699");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48700");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48701");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48702");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48703");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48704");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-2860");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52585");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52589");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52590");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52591");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52593");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52614");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52616");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52620");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52635");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52645");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52646");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52652");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-6270");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-0639");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-0841");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-2201");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-22099");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-23307");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-23848");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-23850");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26601");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26610");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26656");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26671");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26673");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26675");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26679");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26687");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26688");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26700");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26702");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26733");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26739");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26764");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26766");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26772");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26773");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26783");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26791");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26792");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26816");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26817");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26820");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26825");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26830");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26833");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26836");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26840");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26843");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26852");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26853");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26855");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26856");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26857");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26861");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26862");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26866");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26872");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26875");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26876");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26877");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26878");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26879");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26881");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26882");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26883");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26884");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26885");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26891");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26893");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26895");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26896");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26897");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26898");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26901");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26903");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26915");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26917");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26927");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26933");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26939");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26948");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26950");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26951");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26955");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26956");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26960");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26965");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26966");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26969");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26970");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26972");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26979");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26981");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26982");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26993");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27013");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27014");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27030");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27038");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27039");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27041");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27042");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27043");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27046");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27056");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27059");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27062");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27389");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-27043");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/15");

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

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'reference':'kernel-azure-5.14.21-150500.33.51.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-azure-5.14.21-150500.33.51.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-azure-devel-5.14.21-150500.33.51.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-azure-devel-5.14.21-150500.33.51.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-devel-azure-5.14.21-150500.33.51.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-source-azure-5.14.21-150500.33.51.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-syms-azure-5.14.21-150500.33.51.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-syms-azure-5.14.21-150500.33.51.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-azure-5.14.21-150500.33.51.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-public-cloud-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-azure-5.14.21-150500.33.51.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-public-cloud-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-azure-devel-5.14.21-150500.33.51.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-public-cloud-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-azure-devel-5.14.21-150500.33.51.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-public-cloud-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-devel-azure-5.14.21-150500.33.51.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-public-cloud-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-source-azure-5.14.21-150500.33.51.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-public-cloud-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-syms-azure-5.14.21-150500.33.51.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-public-cloud-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-syms-azure-5.14.21-150500.33.51.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-public-cloud-release-15.5', 'sles-release-15.5']},
    {'reference':'cluster-md-kmp-azure-5.14.21-150500.33.51.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'cluster-md-kmp-azure-5.14.21-150500.33.51.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'dlm-kmp-azure-5.14.21-150500.33.51.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'dlm-kmp-azure-5.14.21-150500.33.51.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'gfs2-kmp-azure-5.14.21-150500.33.51.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'gfs2-kmp-azure-5.14.21-150500.33.51.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-azure-5.14.21-150500.33.51.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-azure-5.14.21-150500.33.51.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-azure-devel-5.14.21-150500.33.51.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-azure-devel-5.14.21-150500.33.51.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-azure-extra-5.14.21-150500.33.51.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-azure-extra-5.14.21-150500.33.51.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-azure-livepatch-devel-5.14.21-150500.33.51.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-azure-livepatch-devel-5.14.21-150500.33.51.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-azure-optional-5.14.21-150500.33.51.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-azure-optional-5.14.21-150500.33.51.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-azure-vdso-5.14.21-150500.33.51.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-devel-azure-5.14.21-150500.33.51.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-source-azure-5.14.21-150500.33.51.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-syms-azure-5.14.21-150500.33.51.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-syms-azure-5.14.21-150500.33.51.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kselftests-kmp-azure-5.14.21-150500.33.51.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kselftests-kmp-azure-5.14.21-150500.33.51.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'ocfs2-kmp-azure-5.14.21-150500.33.51.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'ocfs2-kmp-azure-5.14.21-150500.33.51.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'reiserfs-kmp-azure-5.14.21-150500.33.51.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'reiserfs-kmp-azure-5.14.21-150500.33.51.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']}
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
