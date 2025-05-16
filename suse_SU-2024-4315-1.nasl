#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2024:4315-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(213014);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/06");

  script_cve_id(
    "CVE-2021-47594",
    "CVE-2022-48674",
    "CVE-2022-48979",
    "CVE-2022-48982",
    "CVE-2022-48983",
    "CVE-2022-48989",
    "CVE-2022-48990",
    "CVE-2023-52915",
    "CVE-2023-52917",
    "CVE-2023-52918",
    "CVE-2023-52921",
    "CVE-2023-52922",
    "CVE-2024-26782",
    "CVE-2024-26906",
    "CVE-2024-26953",
    "CVE-2024-35888",
    "CVE-2024-35937",
    "CVE-2024-35980",
    "CVE-2024-36484",
    "CVE-2024-36883",
    "CVE-2024-36886",
    "CVE-2024-36905",
    "CVE-2024-36953",
    "CVE-2024-36954",
    "CVE-2024-38577",
    "CVE-2024-38589",
    "CVE-2024-38615",
    "CVE-2024-40997",
    "CVE-2024-41016",
    "CVE-2024-41023",
    "CVE-2024-41049",
    "CVE-2024-42131",
    "CVE-2024-43817",
    "CVE-2024-43897",
    "CVE-2024-44932",
    "CVE-2024-44964",
    "CVE-2024-44995",
    "CVE-2024-46681",
    "CVE-2024-46800",
    "CVE-2024-46802",
    "CVE-2024-46804",
    "CVE-2024-46805",
    "CVE-2024-46807",
    "CVE-2024-46810",
    "CVE-2024-46812",
    "CVE-2024-46819",
    "CVE-2024-46821",
    "CVE-2024-46835",
    "CVE-2024-46842",
    "CVE-2024-46853",
    "CVE-2024-46859",
    "CVE-2024-46864",
    "CVE-2024-46871",
    "CVE-2024-47663",
    "CVE-2024-47665",
    "CVE-2024-47667",
    "CVE-2024-47669",
    "CVE-2024-47670",
    "CVE-2024-47671",
    "CVE-2024-47679",
    "CVE-2024-47682",
    "CVE-2024-47693",
    "CVE-2024-47695",
    "CVE-2024-47696",
    "CVE-2024-47697",
    "CVE-2024-47698",
    "CVE-2024-47699",
    "CVE-2024-47701",
    "CVE-2024-47709",
    "CVE-2024-47712",
    "CVE-2024-47713",
    "CVE-2024-47718",
    "CVE-2024-47723",
    "CVE-2024-47728",
    "CVE-2024-47735",
    "CVE-2024-47737",
    "CVE-2024-47742",
    "CVE-2024-47745",
    "CVE-2024-47749",
    "CVE-2024-47756",
    "CVE-2024-47757",
    "CVE-2024-49850",
    "CVE-2024-49851",
    "CVE-2024-49852",
    "CVE-2024-49855",
    "CVE-2024-49861",
    "CVE-2024-49863",
    "CVE-2024-49868",
    "CVE-2024-49870",
    "CVE-2024-49871",
    "CVE-2024-49875",
    "CVE-2024-49877",
    "CVE-2024-49879",
    "CVE-2024-49884",
    "CVE-2024-49891",
    "CVE-2024-49900",
    "CVE-2024-49902",
    "CVE-2024-49903",
    "CVE-2024-49905",
    "CVE-2024-49907",
    "CVE-2024-49908",
    "CVE-2024-49921",
    "CVE-2024-49924",
    "CVE-2024-49925",
    "CVE-2024-49934",
    "CVE-2024-49935",
    "CVE-2024-49938",
    "CVE-2024-49945",
    "CVE-2024-49947",
    "CVE-2024-49950",
    "CVE-2024-49957",
    "CVE-2024-49963",
    "CVE-2024-49965",
    "CVE-2024-49966",
    "CVE-2024-49968",
    "CVE-2024-49981",
    "CVE-2024-49983",
    "CVE-2024-49985",
    "CVE-2024-49989",
    "CVE-2024-50003",
    "CVE-2024-50007",
    "CVE-2024-50008",
    "CVE-2024-50009",
    "CVE-2024-50013",
    "CVE-2024-50017",
    "CVE-2024-50025",
    "CVE-2024-50026",
    "CVE-2024-50031",
    "CVE-2024-50044",
    "CVE-2024-50062",
    "CVE-2024-50067",
    "CVE-2024-50073",
    "CVE-2024-50074",
    "CVE-2024-50077",
    "CVE-2024-50078",
    "CVE-2024-50082",
    "CVE-2024-50089",
    "CVE-2024-50093",
    "CVE-2024-50095",
    "CVE-2024-50096",
    "CVE-2024-50098",
    "CVE-2024-50099",
    "CVE-2024-50103",
    "CVE-2024-50108",
    "CVE-2024-50110",
    "CVE-2024-50115",
    "CVE-2024-50116",
    "CVE-2024-50117",
    "CVE-2024-50124",
    "CVE-2024-50125",
    "CVE-2024-50127",
    "CVE-2024-50128",
    "CVE-2024-50131",
    "CVE-2024-50134",
    "CVE-2024-50135",
    "CVE-2024-50138",
    "CVE-2024-50141",
    "CVE-2024-50146",
    "CVE-2024-50147",
    "CVE-2024-50148",
    "CVE-2024-50150",
    "CVE-2024-50153",
    "CVE-2024-50154",
    "CVE-2024-50155",
    "CVE-2024-50156",
    "CVE-2024-50160",
    "CVE-2024-50167",
    "CVE-2024-50171",
    "CVE-2024-50179",
    "CVE-2024-50180",
    "CVE-2024-50182",
    "CVE-2024-50183",
    "CVE-2024-50184",
    "CVE-2024-50186",
    "CVE-2024-50187",
    "CVE-2024-50188",
    "CVE-2024-50189",
    "CVE-2024-50192",
    "CVE-2024-50194",
    "CVE-2024-50195",
    "CVE-2024-50196",
    "CVE-2024-50198",
    "CVE-2024-50201",
    "CVE-2024-50205",
    "CVE-2024-50208",
    "CVE-2024-50209",
    "CVE-2024-50215",
    "CVE-2024-50218",
    "CVE-2024-50229",
    "CVE-2024-50230",
    "CVE-2024-50232",
    "CVE-2024-50233",
    "CVE-2024-50234",
    "CVE-2024-50236",
    "CVE-2024-50237",
    "CVE-2024-50249",
    "CVE-2024-50255",
    "CVE-2024-50259",
    "CVE-2024-50261",
    "CVE-2024-50264",
    "CVE-2024-50265",
    "CVE-2024-50267",
    "CVE-2024-50268",
    "CVE-2024-50269",
    "CVE-2024-50271",
    "CVE-2024-50273",
    "CVE-2024-50274",
    "CVE-2024-50279",
    "CVE-2024-50282",
    "CVE-2024-50287",
    "CVE-2024-50289",
    "CVE-2024-50290",
    "CVE-2024-50292",
    "CVE-2024-50295",
    "CVE-2024-50298",
    "CVE-2024-50301",
    "CVE-2024-50302",
    "CVE-2024-53052",
    "CVE-2024-53058",
    "CVE-2024-53059",
    "CVE-2024-53060",
    "CVE-2024-53061",
    "CVE-2024-53063",
    "CVE-2024-53066",
    "CVE-2024-53068",
    "CVE-2024-53079",
    "CVE-2024-53085",
    "CVE-2024-53088",
    "CVE-2024-53104",
    "CVE-2024-53110"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2024:4315-1");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2025/03/25");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2025/02/26");

  script_name(english:"SUSE SLES15 / openSUSE 15 Security Update : kernel (SUSE-SU-2024:4315-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 / openSUSE 15 host has packages installed that are affected by multiple vulnerabilities as
referenced in the SUSE-SU-2024:4315-1 advisory.

    The SUSE Linux Enterprise 15 SP5 RT kernel was updated to receive various security bugfixes.

    The following security bugs were fixed:

    - CVE-2021-47594: mptcp: never allow the PM to close a listener subflow (bsc#1226560).
    - CVE-2022-48983: io_uring: Fix a null-ptr-deref in io_tctx_exit_cb() (bsc#1231959).
    - CVE-2024-26782: mptcp: fix double-free on socket dismantle (bsc#1222590).
    - CVE-2024-26906: Fixed invalid vsyscall page read for copy_from_kernel_nofault() (bsc#1223202).
    - CVE-2024-26953: net: esp: fix bad handling of pages from page_pool (bsc#1223656).
    - CVE-2024-35888: erspan: make sure erspan_base_hdr is present in skb->head (bsc#1224518).
    - CVE-2024-35937: wifi: cfg80211: check A-MSDU format more carefully (bsc#1224526).
    - CVE-2024-36883: net: fix out-of-bounds access in ops_init (bsc#1225725).
    - CVE-2024-36886: tipc: fix UAF in error path (bsc#1225730).
    - CVE-2024-36905: tcp: defer shutdown(SEND_SHUTDOWN) for TCP_SYN_RECV sockets (bsc#1225742).
    - CVE-2024-36954: tipc: fix a possible memleak in tipc_buf_append (bsc#1225764).
    - CVE-2024-38589: netrom: fix possible dead-lock in nr_rt_ioctl() (bsc#1226748).
    - CVE-2024-38615: cpufreq: exit() callback is optional (bsc#1226592).
    - CVE-2024-40997: cpufreq: amd-pstate: fix memory leak on CPU EPP exit (bsc#1227853).
    - CVE-2024-41023: sched/deadline: Fix task_struct reference leak (bsc#1228430).
    - CVE-2024-44932: idpf: fix UAFs when destroying the queues (bsc#1229808).
    - CVE-2024-44964: idpf: fix memory leaks and crashes while performing a soft reset (bsc#1230220).
    - CVE-2024-44995: net: hns3: fix a deadlock problem when config TC during resetting (bsc#1230231).
    - CVE-2024-46681: pktgen: use cpus_read_lock() in pg_net_init() (bsc#1230558).
    - CVE-2024-46800: sch/netem: fix use after free in netem_dequeue (bsc#1230827).
    - CVE-2024-47679: vfs: fix race between evice_inodes() and find_inode()&iput() (bsc#1231930).
    - CVE-2024-47701: ext4: avoid OOB when system.data xattr changes underneath the filesystem (bsc#1231920).
    - CVE-2024-47745: mm: call the security_mmap_file() LSM hook in remap_file_pages() (bsc#1232135).
    - CVE-2024-47757: nilfs2: fix potential oob read in nilfs_btree_check_delete() (bsc#1232187).
    - CVE-2024-49868: btrfs: fix a NULL pointer dereference when failed to start a new trasacntion
    (bsc#1232272).
    - CVE-2024-49921: drm/amd/display: Check null pointers before used (bsc#1232371).
    - CVE-2024-49925: fbdev: efifb: Register sysfs groups through driver core (bsc#1232224)
    - CVE-2024-49934: fs/inode: Prevent dump_mapping() accessing invalid dentry.d_name.name (bsc#1232387).
    - CVE-2024-49945: net/ncsi: Disable the ncsi work before freeing the associated structure (bsc#1232165).
    - CVE-2024-49950: Bluetooth: L2CAP: Fix uaf in l2cap_connect (bsc#1232159).
    - CVE-2024-49968: ext4: filesystems without casefold feature cannot be mounted with siphash (bsc#1232264).
    - CVE-2024-49983: ext4: drop ppath from ext4_ext_replay_update_ex() to avoid double-free (bsc#1232096).
    - CVE-2024-49989: drm/amd/display: fix double free issue during amdgpu module unload (bsc#1232483).
    - CVE-2024-50009: cpufreq: amd-pstate: add check for cpufreq_cpu_get's return value (bsc#1232318).
    - CVE-2024-50073: tty: n_gsm: Fix use-after-free in gsm_cleanup_mux (bsc#1232520).
    - CVE-2024-50082: blk-rq-qos: fix crash on rq_qos_wait vs. rq_qos_wake_function race (bsc#1232500).
    - CVE-2024-50089: unicode: Do not special case ignorable code points (bsc#1232860).
    - CVE-2024-50093: thermal: intel: int340x: processor: Fix warning during module unload (bsc#1232877).
    - CVE-2024-50098: scsi: ufs: core: Set SDEV_OFFLINE when UFS is shut down (bsc#1232881).
    - CVE-2024-50108: drm/amd/display: Disable PSR-SU on Parade 08-01 TCON too (bsc#1232884).
    - CVE-2024-50110: xfrm: fix one more kernel-infoleak in algo dumping (bsc#1232885).
    - CVE-2024-50115: KVM: nSVM: Ignore nCR3[4:0] when loading PDPTEs from memory (bsc#1232919).
    - CVE-2024-50125: Bluetooth: SCO: Fix UAF on sco_sock_timeout (bsc#1232928).
    - CVE-2024-50127: net: sched: fix use-after-free in taprio_change() (bsc#1232907).
    - CVE-2024-50128: net: wwan: fix global oob in wwan_rtnl_policy (bsc#1232905).
    - CVE-2024-50134: drm/vboxvideo: Replace fake VLA at end of vbva_mouse_pointer_shape (bsc#1232890).
    - CVE-2024-50135: nvme-pci: fix race condition between reset and nvme_dev_disable() (bsc#1232888).
    - CVE-2024-50138: bpf: Use raw_spinlock_t in ringbuf (bsc#1232935).
    - CVE-2024-50146: net/mlx5e: Do not call cleanup on profile rollback failure (bsc#1233056).
    - CVE-2024-50147: net/mlx5: Fix command bitmask initialization (bsc#1233067).
    - CVE-2024-50153: scsi: target: core: Fix null-ptr-deref in target_alloc_device() (bsc#1233061).
    - CVE-2024-50154: tcp/dccp: Do not use timer_pending() in reqsk_queue_unlink() (bsc#1233070).
    - CVE-2024-50167: be2net: fix potential memory leak in be_xmit() (bsc#1233049).
    - CVE-2024-50171: net: systemport: fix potential memory leak in bcm_sysport_xmit() (bsc#1233057).
    - CVE-2024-50182: secretmem: disable memfd_secret() if arch cannot set direct map (bsc#1233129).
    - CVE-2024-50184: virtio_pmem: Check device status before requesting flush (bsc#1233135).
    - CVE-2024-50186: net: explicitly clear the sk pointer, when pf->create fails (bsc#1233110).
    - CVE-2024-50188: net: phy: dp83869: fix memory corruption when enabling fiber (bsc#1233107).
    - CVE-2024-50192: irqchip/gic-v4: Do not allow a VMOVP on a dying VPE (bsc#1233106).
    - CVE-2024-50195: posix-clock: Fix missing timespec64 check in pc_clock_settime() (bsc#1233103).
    - CVE-2024-50196: pinctrl: ocelot: fix system hang on level based interrupts (bsc#1233113).
    - CVE-2024-50205: ALSA: firewire-lib: Avoid division by zero in apply_constraint_to_size() (bsc#1233293).
    - CVE-2024-50208: RDMA/bnxt_re: Fix a bug while setting up Level-2 PBL pages (bsc#1233117).
    - CVE-2024-50229: nilfs2: fix potential deadlock with newly created symlinks (bsc#1233205).
    - CVE-2024-50230: nilfs2: fix kernel bug due to missing clearing of checked flag (bsc#1233206).
    - CVE-2024-50259: netdevsim: Add trailing zero to terminate the string in
    nsim_nexthop_bucket_activity_write() (bsc#1233214).
    - CVE-2024-50261: macsec: Fix use-after-free while sending the offloading packet (bsc#1233253).
    - CVE-2024-50264: vsock/virtio: Initialization of the dangling pointer occurring in vsk->trans
    (bsc#1233453).
    - CVE-2024-50267: usb: serial: io_edgeport: fix use after free in debug printk (bsc#1233456).
    - CVE-2024-50271: signal: restore the override_rlimit logic (bsc#1233460).
    - CVE-2024-50273: btrfs: reinitialize delayed ref list after deleting it from the list (bsc#1233462).
    - CVE-2024-50274: idpf: avoid vport access in idpf_get_link_ksettings (bsc#1233463).
    - CVE-2024-50279: dm cache: fix out-of-bounds access to the dirty bitset when resizing (bsc#1233468).
    - CVE-2024-50289: media: av7110: fix a spectre vulnerability (bsc#1233478).
    - CVE-2024-50295: net: arc: fix the device for dma_map_single/dma_unmap_single (bsc#1233484).
    - CVE-2024-50298: net: enetc: allocate vf_state during PF probes (bsc#1233487).
    - CVE-2024-53052: io_uring/rw: fix missing NOWAIT check for O_DIRECT start write (bsc#1233548).
    - CVE-2024-53058: net: stmmac: TSO: Fix unbalanced DMA map/unmap for non-paged SKB data (bsc#1233552).
    - CVE-2024-53061: media: s5p-jpeg: prevent buffer overflows (bsc#1233555).
    - CVE-2024-53063: media: dvbdev: prevent the risk of out of memory access (bsc#1233557).
    - CVE-2024-53068: firmware: arm_scmi: Fix slab-use-after-free in scmi_bus_notifier() (bsc#1233561).
    - CVE-2024-53079: mm/thp: fix deferred split unqueue naming and locking (bsc#1233570).
    - CVE-2024-53088: i40e: fix race condition by adding filter's intermediate sync state (bsc#1233580).
    - CVE-2024-53104: media: uvcvideo: Skip parsing frames of type UVC_VS_UNDEFINED in uvc_parse_format
    (bsc#1234025).
    - CVE-2024-53110: vp_vdpa: fix id_table array not null terminated error (bsc#1234085).


Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1082555");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194869");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218644");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220382");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221309");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221333");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222364");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222590");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223202");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223656");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223848");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223919");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223942");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224518");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224526");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224574");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225725");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225730");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225742");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225764");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225812");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226560");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226592");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226631");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226748");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226872");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227853");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228410");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228430");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228486");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228650");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228857");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229312");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229429");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229585");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229752");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229808");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230055");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230220");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230231");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230270");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230558");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230827");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230918");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231083");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231089");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231098");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231101");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231108");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231111");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231132");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231135");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231138");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231169");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231178");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231180");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231181");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231187");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231202");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231434");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231441");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231452");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231465");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231474");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231481");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231537");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231541");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231646");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231849");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231856");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231858");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231859");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231864");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231904");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231916");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231920");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231923");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231930");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231931");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231947");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231952");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231953");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231959");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231978");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232013");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232015");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232016");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232017");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232027");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232028");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232047");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232048");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232050");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232056");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232076");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232080");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232094");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232096");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232098");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232111");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232126");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232134");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232135");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232141");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232142");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232147");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232152");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232159");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232162");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232165");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232180");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232185");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232187");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232189");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232195");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232198");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232201");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232218");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232224");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232232");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232254");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232255");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232264");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232272");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232279");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232287");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232293");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232312");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232317");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232318");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232333");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232334");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232335");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232339");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232349");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232357");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232359");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232362");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232364");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232370");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232371");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232378");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232385");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232387");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232394");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232413");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232416");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232436");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232483");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232500");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232503");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232504");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232507");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232520");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232552");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232757");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232819");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232860");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232870");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232873");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232877");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232878");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232881");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232884");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232885");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232887");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232888");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232890");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232892");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232896");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232897");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232905");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232907");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232919");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232926");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232928");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232935");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233035");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233049");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233051");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233056");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233057");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233061");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233063");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233065");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233067");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233070");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233073");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233074");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233100");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233103");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233104");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233105");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233106");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233107");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233108");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233110");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233111");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233113");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233114");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233117");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233123");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233125");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233129");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233130");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233134");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233135");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233150");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233189");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233191");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233197");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233205");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233206");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233209");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233210");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233211");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233212");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233214");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233216");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233238");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233241");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233253");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233255");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233293");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233350");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233452");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233453");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233454");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233456");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233457");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233458");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233460");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233462");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233463");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233468");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233471");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233476");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233478");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233479");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233481");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233484");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233487");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233490");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233491");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233528");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233548");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233552");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233553");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233554");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233555");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233557");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233560");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233561");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233570");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233577");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233580");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233977");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234012");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234025");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234085");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234093");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234098");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234108");
  # https://lists.suse.com/pipermail/sle-security-updates/2024-December/019997.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?45561e52");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47594");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48674");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48979");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48982");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48983");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48989");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48990");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52915");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52917");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52918");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52921");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52922");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26782");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26906");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26953");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35888");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35937");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35980");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36484");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36883");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36886");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36905");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36953");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36954");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38577");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38589");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38615");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40997");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41016");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41023");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41049");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42131");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43817");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43897");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-44932");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-44964");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-44995");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46681");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46800");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46802");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46804");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46805");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46807");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46810");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46812");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46819");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46821");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46835");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46842");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46853");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46859");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46864");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46871");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47663");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47665");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47667");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47669");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47670");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47671");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47679");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47682");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47693");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47695");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47696");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47697");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47698");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47699");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47701");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47709");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47712");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47713");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47718");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47723");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47728");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47735");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47737");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47742");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47745");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47749");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47756");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47757");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49850");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49851");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49852");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49855");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49861");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49863");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49868");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49870");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49871");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49875");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49877");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49879");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49884");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49891");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49900");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49902");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49903");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49905");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49907");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49908");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49921");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49924");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49925");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49934");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49935");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49938");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49945");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49947");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49950");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49957");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49963");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49965");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49966");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49968");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49981");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49983");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49985");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49989");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50003");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50007");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50008");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50009");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50013");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50017");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50025");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50026");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50031");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50044");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50062");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50067");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50073");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50074");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50077");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50078");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50082");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50089");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50093");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50095");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50096");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50098");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50099");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50103");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50108");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50110");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50115");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50116");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50117");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50124");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50125");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50127");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50128");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50131");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50134");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50135");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50138");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50141");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50146");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50147");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50148");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50150");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50153");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50154");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50155");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50156");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50160");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50167");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50171");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50179");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50180");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50182");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50183");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50184");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50186");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50187");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50188");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50189");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50192");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50194");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50195");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50196");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50198");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50201");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50205");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50208");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50209");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50215");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50218");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50229");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50230");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50232");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50233");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50234");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50236");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50237");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50249");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50255");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50259");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50261");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50264");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50265");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50267");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50268");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50269");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50271");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50273");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50274");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50279");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50282");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50287");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50289");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50290");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50292");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50295");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50298");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50301");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50302");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53052");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53058");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53059");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53060");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53061");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53063");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53066");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53068");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53079");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53085");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53088");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53104");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53110");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-53104");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-5_14_21-150500_13_79-rt");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES|SUSE)") audit(AUDIT_OS_NOT, "SUSE / openSUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+|SUSE([\d.]+))", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE / openSUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES15|SUSE15\.5)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP5", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'cluster-md-kmp-rt-5.14.21-150500.13.79.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'dlm-kmp-rt-5.14.21-150500.13.79.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'gfs2-kmp-rt-5.14.21-150500.13.79.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-devel-rt-5.14.21-150500.13.79.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-rt-5.14.21-150500.13.79.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-rt-devel-5.14.21-150500.13.79.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-rt-extra-5.14.21-150500.13.79.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-rt-livepatch-5.14.21-150500.13.79.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-rt-livepatch-devel-5.14.21-150500.13.79.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-rt-optional-5.14.21-150500.13.79.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-rt-vdso-5.14.21-150500.13.79.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-rt_debug-5.14.21-150500.13.79.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-rt_debug-devel-5.14.21-150500.13.79.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-rt_debug-vdso-5.14.21-150500.13.79.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-source-rt-5.14.21-150500.13.79.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-syms-rt-5.14.21-150500.13.79.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kselftests-kmp-rt-5.14.21-150500.13.79.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'ocfs2-kmp-rt-5.14.21-150500.13.79.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'reiserfs-kmp-rt-5.14.21-150500.13.79.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-livepatch-5_14_21-150500_13_79-rt-1-150500.11.3.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.5']}
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
