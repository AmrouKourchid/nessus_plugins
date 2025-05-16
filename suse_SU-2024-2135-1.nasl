#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2024:2135-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(200853);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/28");

  script_cve_id(
    "CVE-2023-0160",
    "CVE-2023-6238",
    "CVE-2023-6270",
    "CVE-2023-6531",
    "CVE-2023-7042",
    "CVE-2023-47233",
    "CVE-2023-52434",
    "CVE-2023-52458",
    "CVE-2023-52463",
    "CVE-2023-52472",
    "CVE-2023-52483",
    "CVE-2023-52492",
    "CVE-2023-52503",
    "CVE-2023-52591",
    "CVE-2023-52608",
    "CVE-2023-52616",
    "CVE-2023-52618",
    "CVE-2023-52631",
    "CVE-2023-52635",
    "CVE-2023-52640",
    "CVE-2023-52641",
    "CVE-2023-52645",
    "CVE-2023-52652",
    "CVE-2023-52653",
    "CVE-2023-52654",
    "CVE-2023-52655",
    "CVE-2023-52657",
    "CVE-2023-52658",
    "CVE-2023-52659",
    "CVE-2023-52660",
    "CVE-2023-52661",
    "CVE-2023-52662",
    "CVE-2023-52663",
    "CVE-2023-52664",
    "CVE-2023-52667",
    "CVE-2023-52669",
    "CVE-2023-52670",
    "CVE-2023-52671",
    "CVE-2023-52673",
    "CVE-2023-52674",
    "CVE-2023-52675",
    "CVE-2023-52676",
    "CVE-2023-52678",
    "CVE-2023-52679",
    "CVE-2023-52680",
    "CVE-2023-52681",
    "CVE-2023-52683",
    "CVE-2023-52685",
    "CVE-2023-52686",
    "CVE-2023-52687",
    "CVE-2023-52690",
    "CVE-2023-52691",
    "CVE-2023-52692",
    "CVE-2023-52693",
    "CVE-2023-52694",
    "CVE-2023-52695",
    "CVE-2023-52696",
    "CVE-2023-52697",
    "CVE-2023-52698",
    "CVE-2023-52771",
    "CVE-2023-52772",
    "CVE-2023-52860",
    "CVE-2023-52882",
    "CVE-2024-0639",
    "CVE-2024-21823",
    "CVE-2024-22099",
    "CVE-2024-23848",
    "CVE-2024-24861",
    "CVE-2024-25739",
    "CVE-2024-26601",
    "CVE-2024-26611",
    "CVE-2024-26614",
    "CVE-2024-26632",
    "CVE-2024-26638",
    "CVE-2024-26642",
    "CVE-2024-26643",
    "CVE-2024-26652",
    "CVE-2024-26654",
    "CVE-2024-26656",
    "CVE-2024-26657",
    "CVE-2024-26671",
    "CVE-2024-26673",
    "CVE-2024-26674",
    "CVE-2024-26675",
    "CVE-2024-26679",
    "CVE-2024-26684",
    "CVE-2024-26685",
    "CVE-2024-26692",
    "CVE-2024-26696",
    "CVE-2024-26697",
    "CVE-2024-26704",
    "CVE-2024-26714",
    "CVE-2024-26726",
    "CVE-2024-26731",
    "CVE-2024-26733",
    "CVE-2024-26736",
    "CVE-2024-26737",
    "CVE-2024-26739",
    "CVE-2024-26740",
    "CVE-2024-26742",
    "CVE-2024-26756",
    "CVE-2024-26757",
    "CVE-2024-26760",
    "CVE-2024-26761",
    "CVE-2024-26764",
    "CVE-2024-26769",
    "CVE-2024-26772",
    "CVE-2024-26773",
    "CVE-2024-26774",
    "CVE-2024-26775",
    "CVE-2024-26779",
    "CVE-2024-26783",
    "CVE-2024-26786",
    "CVE-2024-26791",
    "CVE-2024-26793",
    "CVE-2024-26794",
    "CVE-2024-26802",
    "CVE-2024-26805",
    "CVE-2024-26807",
    "CVE-2024-26815",
    "CVE-2024-26816",
    "CVE-2024-26822",
    "CVE-2024-26828",
    "CVE-2024-26832",
    "CVE-2024-26836",
    "CVE-2024-26844",
    "CVE-2024-26846",
    "CVE-2024-26848",
    "CVE-2024-26853",
    "CVE-2024-26854",
    "CVE-2024-26855",
    "CVE-2024-26856",
    "CVE-2024-26857",
    "CVE-2024-26858",
    "CVE-2024-26860",
    "CVE-2024-26861",
    "CVE-2024-26862",
    "CVE-2024-26866",
    "CVE-2024-26868",
    "CVE-2024-26870",
    "CVE-2024-26878",
    "CVE-2024-26881",
    "CVE-2024-26882",
    "CVE-2024-26883",
    "CVE-2024-26884",
    "CVE-2024-26885",
    "CVE-2024-26898",
    "CVE-2024-26899",
    "CVE-2024-26900",
    "CVE-2024-26901",
    "CVE-2024-26903",
    "CVE-2024-26906",
    "CVE-2024-26909",
    "CVE-2024-26921",
    "CVE-2024-26922",
    "CVE-2024-26923",
    "CVE-2024-26925",
    "CVE-2024-26928",
    "CVE-2024-26932",
    "CVE-2024-26933",
    "CVE-2024-26934",
    "CVE-2024-26935",
    "CVE-2024-26937",
    "CVE-2024-26938",
    "CVE-2024-26940",
    "CVE-2024-26943",
    "CVE-2024-26945",
    "CVE-2024-26946",
    "CVE-2024-26948",
    "CVE-2024-26949",
    "CVE-2024-26950",
    "CVE-2024-26951",
    "CVE-2024-26956",
    "CVE-2024-26957",
    "CVE-2024-26958",
    "CVE-2024-26960",
    "CVE-2024-26961",
    "CVE-2024-26962",
    "CVE-2024-26963",
    "CVE-2024-26964",
    "CVE-2024-26972",
    "CVE-2024-26973",
    "CVE-2024-26978",
    "CVE-2024-26979",
    "CVE-2024-26981",
    "CVE-2024-26982",
    "CVE-2024-26983",
    "CVE-2024-26984",
    "CVE-2024-26986",
    "CVE-2024-26988",
    "CVE-2024-26989",
    "CVE-2024-26990",
    "CVE-2024-26991",
    "CVE-2024-26992",
    "CVE-2024-26993",
    "CVE-2024-26994",
    "CVE-2024-26995",
    "CVE-2024-26996",
    "CVE-2024-26997",
    "CVE-2024-26999",
    "CVE-2024-27000",
    "CVE-2024-27001",
    "CVE-2024-27002",
    "CVE-2024-27003",
    "CVE-2024-27004",
    "CVE-2024-27008",
    "CVE-2024-27013",
    "CVE-2024-27014",
    "CVE-2024-27022",
    "CVE-2024-27027",
    "CVE-2024-27028",
    "CVE-2024-27029",
    "CVE-2024-27030",
    "CVE-2024-27031",
    "CVE-2024-27036",
    "CVE-2024-27046",
    "CVE-2024-27056",
    "CVE-2024-27057",
    "CVE-2024-27062",
    "CVE-2024-27067",
    "CVE-2024-27080",
    "CVE-2024-27388",
    "CVE-2024-27389",
    "CVE-2024-27393",
    "CVE-2024-27395",
    "CVE-2024-27396",
    "CVE-2024-27398",
    "CVE-2024-27399",
    "CVE-2024-27400",
    "CVE-2024-27401",
    "CVE-2024-27405",
    "CVE-2024-27408",
    "CVE-2024-27410",
    "CVE-2024-27411",
    "CVE-2024-27412",
    "CVE-2024-27413",
    "CVE-2024-27416",
    "CVE-2024-27417",
    "CVE-2024-27418",
    "CVE-2024-27431",
    "CVE-2024-27432",
    "CVE-2024-27434",
    "CVE-2024-27435",
    "CVE-2024-27436",
    "CVE-2024-35784",
    "CVE-2024-35786",
    "CVE-2024-35788",
    "CVE-2024-35789",
    "CVE-2024-35790",
    "CVE-2024-35791",
    "CVE-2024-35794",
    "CVE-2024-35795",
    "CVE-2024-35796",
    "CVE-2024-35799",
    "CVE-2024-35800",
    "CVE-2024-35801",
    "CVE-2024-35803",
    "CVE-2024-35804",
    "CVE-2024-35806",
    "CVE-2024-35808",
    "CVE-2024-35809",
    "CVE-2024-35810",
    "CVE-2024-35811",
    "CVE-2024-35812",
    "CVE-2024-35813",
    "CVE-2024-35814",
    "CVE-2024-35815",
    "CVE-2024-35817",
    "CVE-2024-35819",
    "CVE-2024-35821",
    "CVE-2024-35822",
    "CVE-2024-35823",
    "CVE-2024-35824",
    "CVE-2024-35825",
    "CVE-2024-35828",
    "CVE-2024-35829",
    "CVE-2024-35830",
    "CVE-2024-35833",
    "CVE-2024-35834",
    "CVE-2024-35835",
    "CVE-2024-35836",
    "CVE-2024-35837",
    "CVE-2024-35838",
    "CVE-2024-35841",
    "CVE-2024-35842",
    "CVE-2024-35845",
    "CVE-2024-35847",
    "CVE-2024-35849",
    "CVE-2024-35850",
    "CVE-2024-35851",
    "CVE-2024-35852",
    "CVE-2024-35854",
    "CVE-2024-35860",
    "CVE-2024-35861",
    "CVE-2024-35862",
    "CVE-2024-35863",
    "CVE-2024-35864",
    "CVE-2024-35865",
    "CVE-2024-35866",
    "CVE-2024-35867",
    "CVE-2024-35868",
    "CVE-2024-35869",
    "CVE-2024-35870",
    "CVE-2024-35872",
    "CVE-2024-35875",
    "CVE-2024-35877",
    "CVE-2024-35878",
    "CVE-2024-35879",
    "CVE-2024-35883",
    "CVE-2024-35885",
    "CVE-2024-35887",
    "CVE-2024-35889",
    "CVE-2024-35891",
    "CVE-2024-35895",
    "CVE-2024-35901",
    "CVE-2024-35903",
    "CVE-2024-35904",
    "CVE-2024-35905",
    "CVE-2024-35907",
    "CVE-2024-35909",
    "CVE-2024-35911",
    "CVE-2024-35912",
    "CVE-2024-35914",
    "CVE-2024-35915",
    "CVE-2024-35916",
    "CVE-2024-35917",
    "CVE-2024-35921",
    "CVE-2024-35922",
    "CVE-2024-35924",
    "CVE-2024-35927",
    "CVE-2024-35928",
    "CVE-2024-35930",
    "CVE-2024-35931",
    "CVE-2024-35932",
    "CVE-2024-35933",
    "CVE-2024-35935",
    "CVE-2024-35936",
    "CVE-2024-35937",
    "CVE-2024-35938",
    "CVE-2024-35940",
    "CVE-2024-35943",
    "CVE-2024-35944",
    "CVE-2024-35945",
    "CVE-2024-35946",
    "CVE-2024-35947",
    "CVE-2024-35950",
    "CVE-2024-35951",
    "CVE-2024-35952",
    "CVE-2024-35953",
    "CVE-2024-35954",
    "CVE-2024-35955",
    "CVE-2024-35956",
    "CVE-2024-35958",
    "CVE-2024-35959",
    "CVE-2024-35960",
    "CVE-2024-35961",
    "CVE-2024-35963",
    "CVE-2024-35964",
    "CVE-2024-35965",
    "CVE-2024-35966",
    "CVE-2024-35967",
    "CVE-2024-35969",
    "CVE-2024-35971",
    "CVE-2024-35972",
    "CVE-2024-35973",
    "CVE-2024-35974",
    "CVE-2024-35975",
    "CVE-2024-35977",
    "CVE-2024-35978",
    "CVE-2024-35981",
    "CVE-2024-35982",
    "CVE-2024-35984",
    "CVE-2024-35986",
    "CVE-2024-35989",
    "CVE-2024-35990",
    "CVE-2024-35991",
    "CVE-2024-35992",
    "CVE-2024-35995",
    "CVE-2024-35997",
    "CVE-2024-35999",
    "CVE-2024-36002",
    "CVE-2024-36006",
    "CVE-2024-36007",
    "CVE-2024-36009",
    "CVE-2024-36011",
    "CVE-2024-36012",
    "CVE-2024-36013",
    "CVE-2024-36014",
    "CVE-2024-36015",
    "CVE-2024-36016",
    "CVE-2024-36018",
    "CVE-2024-36019",
    "CVE-2024-36020",
    "CVE-2024-36021",
    "CVE-2024-36025",
    "CVE-2024-36026",
    "CVE-2024-36029",
    "CVE-2024-36030",
    "CVE-2024-36032",
    "CVE-2024-36880",
    "CVE-2024-36885",
    "CVE-2024-36890",
    "CVE-2024-36891",
    "CVE-2024-36893",
    "CVE-2024-36894",
    "CVE-2024-36895",
    "CVE-2024-36896",
    "CVE-2024-36897",
    "CVE-2024-36898",
    "CVE-2024-36906",
    "CVE-2024-36918",
    "CVE-2024-36921",
    "CVE-2024-36922",
    "CVE-2024-36928",
    "CVE-2024-36930",
    "CVE-2024-36931",
    "CVE-2024-36936",
    "CVE-2024-36940",
    "CVE-2024-36941",
    "CVE-2024-36942",
    "CVE-2024-36944",
    "CVE-2024-36947",
    "CVE-2024-36949",
    "CVE-2024-36950",
    "CVE-2024-36951",
    "CVE-2024-36955",
    "CVE-2024-36959",
    "CVE-2024-267600"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2024:2135-1");

  script_name(english:"SUSE SLES15 / openSUSE 15 Security Update : kernel (SUSE-SU-2024:2135-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 / SLES_SAP15 / openSUSE 15 host has packages installed that are affected by multiple
vulnerabilities as referenced in the SUSE-SU-2024:2135-1 advisory.

    The SUSE Linux Enterprise 15 SP6 Azure kernel was updated to receive various security bugfixes.

    The following security bugs were fixed:

    - CVE-2024-22099: Fixed a null-pointer-dereference in rfcomm_check_security (bsc#1219170).
    - CVE-2024-26764: Fixed IOCB_AIO_RW check in fs/aio before the struct aio_kiocb conversion (bsc#1222721).
    - CVE-2024-26862: Fixed packet annotate data-races around ignore_outgoing (bsc#1223111).
    - CVE-2024-26673: Fixed netfilter/nft_ct layer 3 and 4 protocol sanitization (bsc#1222368).
    - CVE-2023-0160: Fixed deadlock flaw in BPF that could allow a local user to potentially crash the system
    (bsc#1209657).
    - CVE-2024-26993: Fixed fs/sysfs reference leak in sysfs_break_active_protection() (bsc#1223693).
    - CVE-2024-27013: Fixed tun limit printing rate when illegal packet received by tun device (bsc#1223745).
    - CVE-2024-27014: Fixed net/mlx5e to prevent deadlock while disabling aRFS (bsc#1223735).
    - CVE-2024-26948: Fixed drm/amd/display by adding dc_state NULL check in dc_state_release (bsc#1223664).
    - CVE-2024-27056: Fixed wifi/iwlwifi/mvm to ensure offloading TID queue exists (bsc#1223822).
    - CVE-2024-26960: Fixed mm/swap race between free_swap_and_cache() and swapoff() (bsc#1223655).
    - CVE-2023-52652: Fixed NTB for possible name leak in ntb_register_device() (bsc#1223686).
    - CVE-2024-23848: Fixed media/cec for possible use-after-free in cec_queue_msg_fh (bsc#1219104).
    - CVE-2024-26982: Fixed Squashfs inode number check not to be an invalid value of zero (bsc#1223634).
    - CVE-2024-26878: Fixed quota for potential NULL pointer dereference (bsc#1223060).
    - CVE-2024-26901: Fixed do_sys_name_to_handle() to use kzalloc() to prevent kernel-infoleak (bsc#1223198).
    - CVE-2024-26671: Fixed blk-mq IO hang from sbitmap wakeup race (bsc#1222357).
    - CVE-2024-26772: Fixed ext4 to avoid allocating blocks from corrupted group in ext4_mb_find_by_goal()
    (bsc#1222613).
    - CVE-2024-26906: Disallowed vsyscall page read for copy_from_kernel_nofault() (bsc#1223202).
    - CVE-2024-26816: Ignore relocations in .notes section when building with CONFIG_XEN_PV=y (bsc#1222624).
    - CVE-2024-26783: Fixed mm/vmscan bug when calling wakeup_kswapd() with a wrong zone index (bsc#1222615).
    - CVE-2024-26883: Fixed bpf stackmap overflow check on 32-bit arches (bsc#1223035).
    - CVE-2024-26884: Fixed bpf hashtab overflow check on 32-bit arches (bsc#1223189).
    - CVE-2024-26885: Fixed bpf DEVMAP_HASH overflow check on 32-bit arches (bsc#1223190).
    - CVE-2024-26882: Fixed net/ip_tunnel to make sure to pull inner header in ip_tunnel_rcv() (bsc#1223034).
    - CVE-2023-52645: Fixed pmdomain/mediatek race conditions with genpd (bsc#1223033).
    - CVE-2024-26836: Fixed platform/x86/think-lmi password opcode ordering for workstations (bsc#1222968).
    - CVE-2024-26601: Fixed ext4 buddy bitmap corruption via fast commit replay (bsc#1220342).
    - CVE-2024-26773: Fixed ext4 block allocation from corrupted group in ext4_mb_try_best_found()
    (bsc#1222618).
    - CVE-2024-26807: Fixed spi/cadence-qspi NULL pointer reference in runtime PM hooks (bsc#1222801).
    - CVE-2024-26737: Fixed selftests/bpf racing between bpf_timer_cancel_and_free and bpf_timer_cancel
    (bsc#1222557).
    - CVE-2024-26733: Fixed an overflow in arp_req_get() in arp (bsc#1222585).
    - CVE-2024-26684: Fixed net/stmmac/xgmac handling of DPP safety error for DMA channels (bsc#1222445).
    - CVE-2024-26704: Fixed a double-free of blocks due to wrong extents moved_len in ext4 (bsc#1222422).
    - CVE-2023-52591: Fixed a possible reiserfs filesystem corruption via directory renaming (bsc#1221044).
    - CVE-2023-52503: Fixed tee/amdtee use-after-free vulnerability in amdtee_close_session (bsc#1220915).
    - CVE-2024-26642: Fixed the set of anonymous timeout flag in netfilter nf_tables (bsc#1221830).
    - CVE-2024-26614: Fixed the initialization of accept_queue's spinlocks (bsc#1221293).
    - CVE-2024-25739: Fixed possible crash in create_empty_lvol() in drivers/mtd/ubi/vtbl.c (bsc#1219834).
    - CVE-2023-6270: Fixed a use-after-free issue in aoecmd_cfg_pkts (bsc#1218562).
    - CVE-2024-36030: Fix the double free in rvu_npc_freemem() (bsc#1225712)
    - CVE-2023-52698: Fix memory leak in netlbl_calipso_add_pass() (bsc#1224621)
    - CVE-2024-26860: Fix a memory leak when rechecking the data (bsc#1223077).
    - CVE-2023-52772: Fix use-after-free in unix_stream_read_actor() (bsc#1224989).
    - CVE-2024-27431: Zero-initialise xdp_rxq_info struct before running XDP program (bsc#1224718).
    - CVE-2024-35860: Support deferring bpf_link dealloc to after RCU grace period BPF link for some program
    types (bsc#1224531).
    - CVE-2024-35964: Fix not validating setsockopt user input Check user input length before copying data
    (bsc#1224581).
    - CVE-2023-0160: Prevent lock inversion deadlock in map delete elem  (bsc#1209657).
    - CVE-2024-35903: Fix IP after emitting call depth accounting Adjust the IP passed to `emit_patch` so it
    calculates the correct offset for the CALL instruction if `x86_call_depth_emit_accounting` emits code
    (bsc#1224493).
    - CVE-2024-35931: Skip do PCI error slot reset during RAS recovery (bsc#1224652).
    - CVE-2024-35877: Fix VM_PAT handling in COW mappings (bsc#1224525).
    - CVE-2024-35969: Fix race condition between ipv6_get_ifaddr and ipv6_del_addr (bsc#1224580)
    - CVE-2024-35852: Fix memory leak when canceling rehash work The rehash delayed work is rescheduled with a
    delay if the number of credits at end of the work is not negative as supposedly it means that the
    migration ended (bsc#1224502).
    - CVE-2024-36006: Fix incorrect list API usage (bsc#1224541).
    - CVE-2024-36007: Fix warning during rehash (bsc#1224543).
    - CVE-2024-35872: Fix GUP-fast succeeding on secretmem folios (bsc#1224530).
    - CVE-2024-35956: Fix qgroup prealloc rsv leak in subvolume operations (bsc#1224674)
    - CVE-2023-52771: Fix delete_endpoint() vs parent unregistration race  (bsc#1225007).
    - CVE-2024-27408: Add sync read before starting the  DMA transfer in remote setup (bsc#1224430).
    - CVE-2024-35943: Add a null pointer check to the omap_prm_domain_init devm_kasprintf()returns a pointer
    to dynamically allocated memory which can be NULL upon failure (bsc#1224649).
    - CVE-2024-35921: Fix oops when HEVC init fails (bsc#1224477).
    - CVE-2023-52860: Use cpuhp_state_remove_instance_nocalls() for hisi_hns3_pmu uninit process
    (bsc#1224936).
    - CVE-2024-35991: kABI workaround for struct idxd_evl (bsc#1224553).
    - CVE-2024-35854: Fix possible use-after-free during rehash (bsc#1224636).
    - CVE-2024-27418: Take ownership of skb in mctp_local_output (bsc#1224720)
    - CVE-2024-27417: Fix potential 'struct net' leak in inet6_rtm_getaddr() (bsc#1224721).
    - CVE-2024-35905: Protect against int overflow for stack access size (bsc#1224488).
    - CVE-2024-35917: Fix bpf_plt pointer arithmetic (bsc#1224481).
    - CVE-2023-52674: Add clamp() in scarlett2_mixer_ctl_put() to nsure the value passed to
    scarlett2_mixer_ctl_put() is between 0 and SCARLETT2_MIXER_MAX_VALUE so we don't attempt to access outside
    scarlett2_mixer_values[] (bsc#1224727).
    - CVE-2023-52680: Add missing error checks to *_ctl_get() because the *_ctl_get() functions which call
    scarlett2_update_*() were not checking the return value (bsc#1224608).
    - CVE-2023-52692: Add missing error check to scarlett2_usb_set_config() scarlett2_usb_set_config() calls
    scarlett2_usb_get() but was not checking the result (bsc#1224628).
    - CVE-2024-35944: Fix memcpy() run-time warning in dg_dispatch_as_host() Syzkaller hit 'WARNING in
    dg_dispatch_as_host' bug (bsc#1224648).
    - CVE-2024-26923: Suppress false-positive lockdep splat for spin_lock()  in __unix_gc() (bsc#1223384).
    - CVE-2023-52659: Ensure input to pfn_to_kaddr() is treated as a 64-bit type (bsc#1224442).
    - CVE-2024-21823: Hardware logic with insecure de-synchronization in Intel(R) DSA and Intel(R) IAA for
    some Intel(R) 4th or 5th generation Xeon(R) processors may have allowed an authorized user to potentially
    enable denial of service via local access (bsc#1223625).
    - CVE-2024-26828: Fix underflow in parse_server_interfaces() (bsc#1223084).
    - CVE-2024-27395: Fix Use-After-Free in ovs_ct_exit Since kfree_rcu (bsc#1224098).
    - CVE-2023-52483: Perform route lookups under a RCU read-side lock (bsc#1220738).
    - CVE-2024-27396: Fix Use-After-Free in gtp_dellink (bsc#1224096).
    - CVE-2024-26632: Fix iterating over an empty bio with  bio_for_each_folio_all (bsc#1221635).
    - CVE-2024-27401: Ensure that packet_buffer_get respects the user_length provided. (bsc#1224181).
    - CVE-2024-26775: Avoid potential deadlock at set_capacity (bsc#1222627).
    - CVE-2024-26958: Fix UAF in direct writes (bsc#1223653).
    - CVE-2024-26643: Mark set as dead when unbinding anonymous set with timeout While the rhashtable set gc
    runs asynchronously, a race allowed it to collect elements from anonymous sets with timeouts while it is
    being released from the commit path. (bsc#1221829).
    - CVE-2023-52618: Check for unlikely string overflow (bsc#1221615).
    - CVE-2023-6238: Only privileged user could specify a small meta buffer and let the device perform larger
    Direct Memory Access (DMA) into the same buffer, overwriting unrelated kernel memory, causing random
    kernel crashes and memory corruption (bsc#1217384).
    - CVE-2024-26946: Use copy_from_kernel_nofault() to read from unsafe address Read from an unsafe address
    with copy_from_kernel_nofault() in arch_adjust_kprobe_addr() because this function is used before checking
    the address is in text or not (bsc#1223669).
    - CVE-2024-26945: Fix nr_cpus nr_iaa case If nr_cpus nr_iaa, the calculated cpus_per_iaa will be 0, which
    causes a divide-by-0 in rebalance_wq_table() (bsc#1223732).
    - CVE-2024-26679: Read sk->sk_family once in inet_recv_error() inet_recv_error() is called without holding
    the socket lock. IPv6 socket could mutate to IPv4 with IPV6_ADDRFORM socket option and trigger a KCSAN
    warning (bsc#1222385).
    - CVE-2024-26791: Properly validate device names (bsc#1222793)
    - CVE-2023-52641: Add NULL ptr dereference checking at the end of attr_allocate_frame() (bsc#1222303)
    - CVE-2024-26726: Do not drop extent_map for free space inode on write error (bsc#1222532)
    - CVE-2024-27022: Defer linking file vma until vma is fully initialized (bsc#1223774).
    - CVE-2024-26899: Fix deadlock between bd_link_disk_holder and partition scan (bsc#1223045).
    - CVE-2024-26638: Always initialize struct msghdr completely (bsc#1221649).
    - CVE-2024-26909: Fix drm bridge use-after-free A recent DRM series purporting to simplify support
    (bsc#1223143).
    - CVE-2024-26674: Revert to _ASM_EXTABLE_UA() for {get,put}_user() fixups (bsc#1222378).
    - CVE-2024-26832: Fix missing folio cleanup in writeback race path (bsc#1223007).
    - CVE-2024-26844: Fix WARNING in _copy_from_iter (bsc#1223015).
    - CVE-2024-26774: Avoid dividing by 0 in mb_update_avg_fragment_size() when block bitmap corrupt
    (bsc#1222622).
    - CVE-2024-26815: Properly check TCA_TAPRIO_TC_ENTRY_INDEX (bsc#1222635).
    - cve-2024-267600: Fix bio_put() for error case (bsc#1222596).
    - CVE-2024-26731: Fix NULL pointer dereference in sk_psock_verdict_data_ready() (bsc#1222371).
    - CVE-2024-26740: Use the backlog for mirred ingress (bsc#1222563).
    - CVE-2023-52640: Fix oob in ntfs_listxattr The length of name cannot exceed the space occupied by ea
    (bsc#1222301).
    - CVE-2023-52631: Fix a NULL dereference bug (bsc#1222264).
    - CVE-2023-52458: Add check that partition length needs to be aligned  with block size (bsc#1220428).
    - CVE-2023-6270: Fix the potential use-after-free problem in aoecmd_cfg_pkts  (bsc#1218562).
    - CVE-2024-26805: Fix kernel-infoleak-after-free in __skb_datagram_iter (bsc#1222630).
    - CVE-2024-26991: Do not overflow lpage_info when checking attributes (bsc#1223695).

    - CVE-2024-26921: Preserve kabi for sk_buff (bsc#1223138).
    - CVE-2024-26925: Release mutex after nft_gc_seq_end from abort path (bsc#1223390).
    - CVE-2024-26822: Set correct id, uid and cruid for multiuser  automounts (bsc#1223011).
    - CVE-2023-52434: Fixed potential OOBs in smb2_parse_contexts()  (bsc#1220148).
    - CVE-2024-26928: Fixed potential UAF in cifs_debug_files_proc_show() (bsc#1223532).
    - CVE-2024-35999: Fixed missing lock when picking channel (bsc#1224550).
    - CVE-2024-35861: Fixed potential UAF in  cifs_signal_cifsd_for_reconnect() (bsc#1224766).
    - CVE-2024-35862: Fixed potential UAF in smb2_is_network_name_deleted()  (bsc#1224764).
    - CVE-2024-35863: Fixed potential UAF in is_valid_oplock_break() (bsc#1224763).
    - CVE-2024-35865: Fixed potential UAF in smb2_is_valid_oplock_break()  (bsc#1224668).
    - CVE-2024-35864: Fixed potential UAF in smb2_is_valid_lease_break()  (bsc#1224765).
    - CVE-2024-35867: Fixed potential UAF in cifs_stats_proc_show() (bsc#1224664).
    - CVE-2024-35868: Fixed potential UAF in cifs_stats_proc_write() (bsc#1224678).
    - CVE-2024-35866: Fixed potential UAF in cifs_dump_full_key()  (bsc#1224667).
    - CVE-2024-35869: Guarantee refcounted children from parent session  (bsc#1224679).
    - CVE-2024-35870: Fixed UAF in smb2_reconnect_server() (bsc#1224672).
    - CVE-2024-26692: Fixed regression in writes when non-standard maximum write  size negotiated
    (bsc#1222464).
    - CVE-2024-27036: Fixed writeback data corruption (bsc#1223810).


Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1012628");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1065729");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1181674");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187716");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193599");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194869");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207948");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208593");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209657");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213573");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214852");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215199");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1216196");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1216358");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1216702");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217169");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217384");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217408");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217489");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217750");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217959");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218205");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218336");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218447");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218562");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218779");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218917");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219104");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219170");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219596");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219623");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219834");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220021");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220045");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220120");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220148");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220328");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220342");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220428");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220430");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220569");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220587");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220738");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220783");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220915");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221044");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221276");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221293");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221303");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221375");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221504");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221612");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221615");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221635");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221645");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221649");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221765");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221777");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221783");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221816");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221829");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221830");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221858");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222115");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222173");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222264");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222273");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222294");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222301");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222303");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222304");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222307");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222357");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222366");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222368");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222371");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222378");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222379");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222385");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222422");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222426");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222428");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222437");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222445");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222459");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222464");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222489");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222522");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222525");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222527");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222531");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222532");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222549");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222550");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222557");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222559");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222563");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222585");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222586");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222596");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222606");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222608");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222613");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222615");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222618");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222622");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222624");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222627");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222630");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222635");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222721");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222727");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222769");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222771");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222772");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222775");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222777");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222780");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222782");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222793");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222799");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222801");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222968");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223007");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223011");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223015");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223016");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223020");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223023");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223024");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223030");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223033");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223034");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223035");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223038");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223039");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223041");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223045");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223046");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223051");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223052");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223058");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223060");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223061");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223076");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223077");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223084");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223111");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223113");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223138");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223143");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223187");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223189");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223190");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223191");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223198");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223202");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223285");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223315");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223338");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223369");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223380");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223384");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223390");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223439");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223462");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223532");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223539");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223575");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223590");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223591");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223592");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223593");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223625");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223628");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223629");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223633");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223634");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223637");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223641");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223643");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223649");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223650");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223651");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223652");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223653");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223654");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223655");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223660");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223661");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223663");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223664");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223665");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223666");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223668");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223669");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223670");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223671");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223675");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223677");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223678");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223686");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223692");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223693");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223695");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223696");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223698");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223705");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223712");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223718");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223728");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223732");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223735");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223739");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223741");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223744");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223745");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223747");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223748");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223749");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223750");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223752");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223754");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223757");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223759");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223761");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223762");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223774");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223782");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223787");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223788");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223789");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223790");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223802");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223805");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223810");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223822");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223827");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223831");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223834");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223838");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223869");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223870");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223871");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223872");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223874");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223944");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223945");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223946");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223991");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224076");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224096");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224098");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224099");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224137");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224166");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224174");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224177");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224180");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224181");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224331");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224348");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224423");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224429");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224430");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224432");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224433");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224437");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224438");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224442");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224443");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224445");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224449");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224477");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224479");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224480");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224481");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224482");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224486");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224487");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224488");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224491");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224492");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224493");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224494");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224495");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224500");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224501");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224502");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224504");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224505");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224506");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224507");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224508");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224509");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224511");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224513");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224517");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224519");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224521");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224524");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224525");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224526");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224530");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224531");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224534");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224537");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224541");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224542");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224543");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224546");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224550");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224552");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224553");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224555");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224557");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224558");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224559");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224562");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224565");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224566");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224567");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224568");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224569");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224571");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224573");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224576");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224577");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224578");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224579");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224580");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224581");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224582");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224585");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224586");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224587");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224588");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224592");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224596");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224598");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224600");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224601");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224602");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224603");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224605");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224607");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224608");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224609");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224611");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224613");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224615");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224617");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224618");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224620");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224621");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224622");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224623");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224624");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224626");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224627");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224628");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224629");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224630");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224632");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224633");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224634");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224636");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224637");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224638");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224639");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224640");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224643");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224644");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224645");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224646");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224647");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224648");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224649");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224650");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224651");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224652");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224653");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224654");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224657");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224660");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224663");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224664");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224665");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224666");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224667");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224668");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224671");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224672");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224674");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224675");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224676");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224677");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224678");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224679");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224680");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224681");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224682");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224683");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224685");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224686");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224687");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224688");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224692");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224696");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224697");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224699");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224701");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224703");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224704");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224705");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224706");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224707");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224709");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224710");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224712");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224714");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224716");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224717");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224718");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224719");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224720");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224721");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224722");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224723");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224725");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224727");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224728");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224729");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224730");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224731");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224732");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224733");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224736");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224738");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224739");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224740");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224741");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224742");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224747");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224749");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224763");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224764");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224765");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224766");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224790");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224792");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224793");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224803");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224804");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224866");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224936");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224989");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225007");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225053");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225133");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225134");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225136");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225172");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225502");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225578");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225579");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225580");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225593");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225605");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225607");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225610");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225616");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225618");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225640");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225642");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225692");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225694");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225695");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225696");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225698");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225699");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225704");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225705");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225708");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225710");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225712");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225714");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225715");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225720");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225722");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225728");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225734");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225735");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225736");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225747");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225748");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225749");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225750");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225756");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225765");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225766");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225769");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225773");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225775");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225842");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225945");
  script_set_attribute(attribute:"see_also", value:"https://lists.suse.com/pipermail/sle-updates/2024-June/035681.html");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-0160");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-47233");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52434");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52458");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52463");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52472");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52483");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52492");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52503");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52591");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52608");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52616");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52618");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52631");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52635");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52640");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52641");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52645");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52652");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52653");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52654");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52655");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52657");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52658");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52659");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52660");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52661");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52662");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52663");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52664");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52667");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52669");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52670");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52671");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52673");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52674");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52675");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52676");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52678");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52679");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52680");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52681");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52683");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52685");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52686");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52687");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52690");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52691");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52692");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52693");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52694");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52695");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52696");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52697");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52698");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52771");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52772");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52860");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52882");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-6238");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-6270");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-6531");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-7042");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-0639");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-21823");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-22099");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-23848");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-24861");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-25739");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26601");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26611");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26614");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26632");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26638");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26642");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26643");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26652");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26654");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26656");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26657");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26671");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26673");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26674");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26675");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26679");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26684");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26685");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26692");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26696");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26697");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26704");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26714");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26726");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26731");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26733");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26736");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26737");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26739");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26740");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26742");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26756");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26757");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26760");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-267600");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26761");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26764");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26769");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26772");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26773");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26774");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26775");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26779");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26783");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26786");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26791");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26793");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26794");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26802");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26805");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26807");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26815");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26816");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26822");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26828");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26832");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26836");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26844");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26846");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26848");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26853");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26854");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26855");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26856");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26857");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26858");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26860");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26861");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26862");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26866");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26868");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26870");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26878");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26881");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26882");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26883");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26884");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26885");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26898");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26899");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26900");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26901");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26903");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26906");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26909");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26921");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26922");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26923");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26925");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26928");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26932");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26933");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26934");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26935");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26937");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26938");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26940");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26943");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26945");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26946");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26948");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26949");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26950");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26951");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26956");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26957");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26958");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26960");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26961");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26962");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26963");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26964");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26972");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26973");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26978");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26979");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26981");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26982");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26983");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26984");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26986");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26988");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26989");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26990");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26991");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26992");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26993");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26994");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26995");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26996");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26997");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26999");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27000");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27001");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27002");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27003");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27004");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27008");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27013");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27014");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27022");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27027");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27028");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27029");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27030");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27031");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27036");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27046");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27056");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27057");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27062");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27067");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27080");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27388");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27389");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27393");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27395");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27396");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27398");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27399");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27400");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27401");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27405");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27408");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27410");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27411");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27412");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27413");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27416");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27417");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27418");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27431");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27432");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27434");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27435");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27436");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35784");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35786");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35788");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35789");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35790");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35791");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35794");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35795");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35796");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35799");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35800");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35801");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35803");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35804");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35806");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35808");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35809");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35810");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35811");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35812");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35813");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35814");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35815");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35817");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35819");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35821");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35822");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35823");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35824");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35825");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35828");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35829");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35830");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35833");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35834");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35835");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35836");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35837");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35838");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35841");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35842");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35845");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35847");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35849");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35850");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35851");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35852");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35854");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35860");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35861");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35862");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35863");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35864");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35865");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35866");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35867");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35868");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35869");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35870");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35872");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35875");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35877");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35878");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35879");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35883");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35885");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35887");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35889");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35891");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35895");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35901");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35903");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35904");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35905");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35907");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35909");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35911");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35912");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35914");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35915");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35916");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35917");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35921");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35922");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35924");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35927");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35928");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35930");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35931");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35932");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35933");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35935");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35936");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35937");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35938");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35940");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35943");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35944");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35945");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35946");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35947");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35950");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35951");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35952");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35953");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35954");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35955");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35956");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35958");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35959");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35960");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35961");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35963");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35964");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35965");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35966");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35967");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35969");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35971");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35972");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35973");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35974");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35975");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35977");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35978");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35981");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35982");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35984");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35986");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35989");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35990");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35991");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35992");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35995");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35997");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35999");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36002");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36006");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36007");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36009");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36011");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36012");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36013");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36014");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36015");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36016");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36018");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36019");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36020");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36021");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36025");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36026");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36029");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36030");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36032");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36880");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36885");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36890");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36891");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36893");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36894");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36895");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36896");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36897");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36898");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36906");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36918");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36921");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36922");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36928");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36930");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36931");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36936");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36940");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36941");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36942");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36944");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36947");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36949");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36950");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36951");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36955");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36959");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-52434");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/06/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/22");

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
if (! preg(pattern:"^(SLES15|SLES_SAP15|SUSE15\.6)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15 / SLES_SAP15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP6", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP15" && (! preg(pattern:"^(6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP15 SP6", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'kernel-azure-6.4.0-150600.8.5.4', 'sp':'6', 'cpu':'aarch64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-azure-6.4.0-150600.8.5.4', 'sp':'6', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-azure-devel-6.4.0-150600.8.5.4', 'sp':'6', 'cpu':'aarch64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-azure-devel-6.4.0-150600.8.5.4', 'sp':'6', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-devel-azure-6.4.0-150600.8.5.4', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-source-azure-6.4.0-150600.8.5.4', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-syms-azure-6.4.0-150600.8.5.1', 'sp':'6', 'cpu':'aarch64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-syms-azure-6.4.0-150600.8.5.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-azure-6.4.0-150600.8.5.4', 'sp':'6', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-azure-6.4.0-150600.8.5.4', 'sp':'6', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-azure-devel-6.4.0-150600.8.5.4', 'sp':'6', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-azure-devel-6.4.0-150600.8.5.4', 'sp':'6', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-devel-azure-6.4.0-150600.8.5.4', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-source-azure-6.4.0-150600.8.5.4', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-syms-azure-6.4.0-150600.8.5.1', 'sp':'6', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-syms-azure-6.4.0-150600.8.5.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'cluster-md-kmp-azure-6.4.0-150600.8.5.4', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'cluster-md-kmp-azure-6.4.0-150600.8.5.4', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'dlm-kmp-azure-6.4.0-150600.8.5.4', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'dlm-kmp-azure-6.4.0-150600.8.5.4', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'gfs2-kmp-azure-6.4.0-150600.8.5.4', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'gfs2-kmp-azure-6.4.0-150600.8.5.4', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-azure-6.4.0-150600.8.5.4', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-azure-6.4.0-150600.8.5.4', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-azure-devel-6.4.0-150600.8.5.4', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-azure-devel-6.4.0-150600.8.5.4', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-azure-extra-6.4.0-150600.8.5.4', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-azure-extra-6.4.0-150600.8.5.4', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-azure-livepatch-devel-6.4.0-150600.8.5.4', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-azure-livepatch-devel-6.4.0-150600.8.5.4', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-azure-optional-6.4.0-150600.8.5.4', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-azure-optional-6.4.0-150600.8.5.4', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-azure-vdso-6.4.0-150600.8.5.4', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-devel-azure-6.4.0-150600.8.5.4', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-source-azure-6.4.0-150600.8.5.4', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-syms-azure-6.4.0-150600.8.5.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-syms-azure-6.4.0-150600.8.5.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kselftests-kmp-azure-6.4.0-150600.8.5.4', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kselftests-kmp-azure-6.4.0-150600.8.5.4', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'ocfs2-kmp-azure-6.4.0-150600.8.5.4', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'ocfs2-kmp-azure-6.4.0-150600.8.5.4', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'reiserfs-kmp-azure-6.4.0-150600.8.5.4', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'reiserfs-kmp-azure-6.4.0-150600.8.5.4', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']}
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
      severity   : SECURITY_HOLE,
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
