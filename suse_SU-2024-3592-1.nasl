#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2024:3592-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(208715);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/11");

  script_cve_id(
    "CVE-2022-48901",
    "CVE-2022-48911",
    "CVE-2022-48923",
    "CVE-2022-48935",
    "CVE-2022-48944",
    "CVE-2022-48945",
    "CVE-2023-52610",
    "CVE-2023-52916",
    "CVE-2024-26640",
    "CVE-2024-26759",
    "CVE-2024-26767",
    "CVE-2024-26804",
    "CVE-2024-26837",
    "CVE-2024-37353",
    "CVE-2024-38538",
    "CVE-2024-38596",
    "CVE-2024-38632",
    "CVE-2024-40910",
    "CVE-2024-40973",
    "CVE-2024-40983",
    "CVE-2024-41062",
    "CVE-2024-41082",
    "CVE-2024-42154",
    "CVE-2024-42259",
    "CVE-2024-42265",
    "CVE-2024-42304",
    "CVE-2024-42305",
    "CVE-2024-42306",
    "CVE-2024-43828",
    "CVE-2024-43835",
    "CVE-2024-43890",
    "CVE-2024-43898",
    "CVE-2024-43912",
    "CVE-2024-43914",
    "CVE-2024-44935",
    "CVE-2024-44944",
    "CVE-2024-44946",
    "CVE-2024-44948",
    "CVE-2024-44950",
    "CVE-2024-44952",
    "CVE-2024-44954",
    "CVE-2024-44967",
    "CVE-2024-44969",
    "CVE-2024-44970",
    "CVE-2024-44971",
    "CVE-2024-44972",
    "CVE-2024-44977",
    "CVE-2024-44982",
    "CVE-2024-44986",
    "CVE-2024-44987",
    "CVE-2024-44988",
    "CVE-2024-44989",
    "CVE-2024-44990",
    "CVE-2024-44998",
    "CVE-2024-44999",
    "CVE-2024-45000",
    "CVE-2024-45001",
    "CVE-2024-45003",
    "CVE-2024-45006",
    "CVE-2024-45007",
    "CVE-2024-45008",
    "CVE-2024-45011",
    "CVE-2024-45013",
    "CVE-2024-45015",
    "CVE-2024-45018",
    "CVE-2024-45020",
    "CVE-2024-45021",
    "CVE-2024-45026",
    "CVE-2024-45028",
    "CVE-2024-45029",
    "CVE-2024-46673",
    "CVE-2024-46674",
    "CVE-2024-46675",
    "CVE-2024-46676",
    "CVE-2024-46677",
    "CVE-2024-46679",
    "CVE-2024-46685",
    "CVE-2024-46686",
    "CVE-2024-46689",
    "CVE-2024-46694",
    "CVE-2024-46702",
    "CVE-2024-46707",
    "CVE-2024-46714",
    "CVE-2024-46715",
    "CVE-2024-46717",
    "CVE-2024-46720",
    "CVE-2024-46721",
    "CVE-2024-46722",
    "CVE-2024-46723",
    "CVE-2024-46724",
    "CVE-2024-46725",
    "CVE-2024-46726",
    "CVE-2024-46727",
    "CVE-2024-46728",
    "CVE-2024-46730",
    "CVE-2024-46731",
    "CVE-2024-46732",
    "CVE-2024-46737",
    "CVE-2024-46738",
    "CVE-2024-46739",
    "CVE-2024-46743",
    "CVE-2024-46744",
    "CVE-2024-46745",
    "CVE-2024-46746",
    "CVE-2024-46747",
    "CVE-2024-46750",
    "CVE-2024-46751",
    "CVE-2024-46752",
    "CVE-2024-46753",
    "CVE-2024-46755",
    "CVE-2024-46756",
    "CVE-2024-46758",
    "CVE-2024-46759",
    "CVE-2024-46761",
    "CVE-2024-46771",
    "CVE-2024-46772",
    "CVE-2024-46773",
    "CVE-2024-46774",
    "CVE-2024-46778",
    "CVE-2024-46780",
    "CVE-2024-46781",
    "CVE-2024-46783",
    "CVE-2024-46784",
    "CVE-2024-46786",
    "CVE-2024-46787",
    "CVE-2024-46791",
    "CVE-2024-46794",
    "CVE-2024-46798",
    "CVE-2024-46822",
    "CVE-2024-46830"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2024:3592-1");

  script_name(english:"SUSE SLES15 / openSUSE 15 Security Update : kernel (SUSE-SU-2024:3592-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 / openSUSE 15 host has packages installed that are affected by multiple vulnerabilities as
referenced in the SUSE-SU-2024:3592-1 advisory.

    The SUSE Linux Enterprise 15 SP5 RT kernel was updated to receive various security bugfixes.


    The following security bugs were fixed:

    - CVE-2022-48901: btrfs: do not start relocation until in progress drops are done  (bsc#1229607).
    - CVE-2022-48911: kabi: add __nf_queue_get_refs() for kabi compliance.  (bsc#1229633).
    - CVE-2022-48923: btrfs: prevent copying too big compressed lzo segment (bsc#1229662)
    - CVE-2022-48935: Fixed an unregister flowtable hooks on netns exit (bsc#1229619)
    - CVE-2023-52610: net/sched: act_ct: fix skb leak and crash on ooo frags (bsc#1221610).
    - CVE-2023-52916: media: aspeed: Fix memory overwrite if timing is 1600x900 (bsc#1230269).
    - CVE-2024-26640: tcp: add sanity checks to rx zerocopy (bsc#1221650).
    - CVE-2024-26759: mm/swap: fix race when skipping swapcache (bsc#1230340).
    - CVE-2024-26767: drm/amd/display: fixed integer types and null check locations  (bsc#1230339).
    - CVE-2024-26804: net: ip_tunnel: prevent perpetual headroom growth (bsc#1222629).
    - CVE-2024-26837: net: bridge: switchdev: race between creation of new group memberships and generation of
    the list of MDB events to replay (bsc#1222973).
    - CVE-2024-37353: virtio: fixed a double free in vp_del_vqs() (bsc#1226875).
    - CVE-2024-38538: net: bridge: xmit: make sure we have at least eth header len bytes (bsc#1226606).
    - CVE-2024-38596: af_unix: Fix data races in unix_release_sock/unix_stream_sendmsg (bsc#1226846).
    - CVE-2024-40910: Fix refcount imbalance on inbound connections (bsc#1227832).
    - CVE-2024-40973: media: mtk-vcodec: potential null pointer deference in SCP (bsc#1227890).
    - CVE-2024-40983: tipc: force a dst refcount before doing decryption (bsc#1227819).
    - CVE-2024-41062: Sync sock recv cb and release (bsc#1228576).
    - CVE-2024-41082: nvme-fabrics: use reserved tag for reg read/write command  (bsc#1228620 CVE-2024-41082).
    - CVE-2024-42154: tcp_metrics: validate source addr length (bsc#1228507).
    - CVE-2024-42259: Fix Virtual Memory mapping boundaries calculation (bsc#1229156)
    - CVE-2024-42265: protect the fetch of ->fd[fd] in do_dup2() from mispredictions (bsc#1229334).
    - CVE-2024-42304: ext4: make sure the first directory block is not a hole (bsc#1229364).
    - CVE-2024-42305: ext4: check dot and dotdot of dx_root before making dir indexed (bsc#1229363).
    - CVE-2024-42306: udf: Avoid using corrupted block bitmap buffer (bsc#1229362).
    - CVE-2024-43828: ext4: fix infinite loop when replaying fast_commit (bsc#1229394).
    - CVE-2024-43890: tracing: Fix overflow in get_free_elt() (bsc#1229764).
    - CVE-2024-43898: ext4: sanity check for NULL pointer after ext4_force_shutdown (bsc#1229753).
    - CVE-2024-43912: wifi: nl80211: disallow setting special AP channel widths (bsc#1229830)
    - CVE-2024-43914: md/raid5: avoid BUG_ON() while continue reshape after reassembling (bsc#1229790).
    - CVE-2024-44935: sctp: Fix null-ptr-deref in reuseport_add_sock() (bsc#1229810).
    - CVE-2024-44944: netfilter: ctnetlink: use helper function to calculate expect ID (bsc#1229899).
    - CVE-2024-44946: kcm: Serialise kcm_sendmsg() for the same socket (bsc#1230015).
    - CVE-2024-44950: serial: sc16is7xx: fix invalid FIFO access with special register set (bsc#1230180).
    - CVE-2024-44952: driver core: Fix uevent_show() vs driver detach race  (bsc#1230178).
    - CVE-2024-44954: ALSA: line6: Fix racy access to midibuf (bsc#1230176).
    - CVE-2024-44970: net/mlx5e: SHAMPO, Fix invalid WQ linked list unlink (bsc#1230209).
    - CVE-2024-44971: net: dsa: bcm_sf2: Fix a possible memory leak in bcm_sf2_mdio_register() (bsc#1230211).
    - CVE-2024-44986: ipv6: fix possible UAF in ip6_finish_output2() (bsc#1230230)
    - CVE-2024-44987: ipv6: prevent UAF in ip6_send_skb() (bsc#1230185).
    - CVE-2024-44988: net: dsa: mv88e6xxx: Fix out-of-bound access (bsc#1230192).
    - CVE-2024-44989: bonding: fix xfrm real_dev null pointer dereference (bsc#1230193).
    - CVE-2024-44990: bonding: fix null pointer deref in bond_ipsec_offload_ok (bsc#1230194).
    - CVE-2024-44998: atm: idt77252: prevent use after free in dequeue_rx() (bsc#1230171).
    - CVE-2024-44999: gtp: pull network headers in gtp_dev_xmit() (bsc#1230233).
    - CVE-2024-45003: Don't evict inode under the inode lru traversing context (bsc#1230245).
    - CVE-2024-45007: char: xillybus: Refine workqueue handling (bsc#1230175).
    - CVE-2024-45008: Input: MT - limit max slots (bsc#1230248).
    - CVE-2024-45013: nvme: move stopping keep-alive into nvme_uninit_ctrl() (bsc#1230442).
    - CVE-2024-45015: drm/msm/dpu: move dpu_encoder's connector assignment to (bsc#1230444)
    - CVE-2024-45018: netfilter: flowtable: initialise extack before use (bsc#1230431).
    - CVE-2024-45021: memcg_write_event_control(): fix a user-triggerable oops (bsc#1230434).
    - CVE-2024-45029: i2c: tegra: Do not mark ACPI devices as irq safe (bsc#1230451).
    - CVE-2024-46673: scsi: aacraid: Fix double-free on probe failure (bsc#1230506).
    - CVE-2024-46674: usb: dwc3: st: fix probed platform device ref count on probe  error path (bsc#1230507).
    - CVE-2024-46677: gtp: fix a potential NULL pointer dereference (bsc#1230549).
    - CVE-2024-46679: ethtool: check device is present when getting link settings (bsc#1230556).
    - CVE-2024-46685: pinctrl: single: fix potential NULL dereference in pcs_get_function() (bsc#1230515)
    - CVE-2024-46686: smb/client: avoid dereferencing rdata=NULL in smb2_new_read_req() (bsc#1230517).
    - CVE-2024-46689: soc: qcom: cmd-db: Map shared memory as WC, not WB (bsc#1230524)
    - CVE-2024-46702: thunderbolt: Mark XDomain as unplugged when router is removed (bsc#1230589)
    - CVE-2024-46707: KVM: arm64: Make ICC_*SGI*_EL1 undef in the absence of a vGICv3  (bsc#1230582).
    - CVE-2024-46715: driver: iio: add missing checks on iio_info's callback access  (bsc#1230700).
    - CVE-2024-46717: net/mlx5e: SHAMPO, Fix incorrect page release (bsc#1230719).
    - CVE-2024-46721: pparmor: fix possible NULL pointer dereference (bsc#1230710)
    - CVE-2024-46728: drm/amd/display: Check index for aux_rd_interval before using (bsc#1230703)
    - CVE-2024-46730: drm/amd/display: Ensure array index tg_inst won't be -1 (bsc#1230701)
    - CVE-2024-46743: of/irq: Prevent device address out-of-bounds read in interrupt map walk (bsc#1230756).
    - CVE-2024-46750: PCI: Add missing bridge lock to pci_bus_lock() (bsc#1230783).
    - CVE-2024-46751: btrfs: do not BUG_ON() when 0 reference count at btrfs_lookup_extent_info()
    (bsc#1230786).
    - CVE-2024-46752: btrfs: reduce nesting for extent processing at btrfs_lookup_extent_info() (bsc#1230794).
    - CVE-2024-46753: btrfs: handle errors from btrfs_dec_ref() properly (bsc#1230796).
    - CVE-2024-46772: drm/amd/display: Check denominator crb_pipes before used (bsc#1230772).
    - CVE-2024-46783: tcp_bpf: fix return value of tcp_bpf_sendmsg() (bsc#1230810).
    - CVE-2024-46787: userfaultfd: fix checks for huge PMDs (bsc#1230815).
    - CVE-2024-46794: x86/tdx: Fix data leak in mmio_read() (bsc#1230825).
    - CVE-2024-46822: arm64: acpi: Harden get_cpu_for_acpi_id() against missing CPU entry (bsc#1231120).
    - CVE-2024-46830: KVM: x86: Acquire kvm->srcu when handling KVM_SET_VCPU_EVENTS  (bsc#1231116).


Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199769");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1216223");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220382");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221610");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221650");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222629");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222973");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223600");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223848");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224085");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225903");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226003");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226606");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226662");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226666");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226846");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226860");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226875");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226915");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227487");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227726");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227819");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227832");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227890");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228507");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228576");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228620");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228771");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229031");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229034");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229086");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229156");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229289");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229334");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229362");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229363");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229364");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229394");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229429");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229453");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229572");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229573");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229585");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229607");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229619");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229633");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229662");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229753");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229764");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229790");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229810");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229830");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229899");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229928");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229947");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230015");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230129");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230130");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230170");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230171");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230174");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230175");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230176");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230178");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230180");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230185");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230192");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230193");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230194");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230200");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230204");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230209");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230211");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230212");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230217");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230224");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230230");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230233");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230244");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230245");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230247");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230248");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230269");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230339");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230340");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230392");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230398");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230431");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230433");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230434");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230440");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230442");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230444");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230450");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230451");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230454");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230506");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230507");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230511");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230515");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230517");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230524");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230533");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230535");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230549");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230556");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230582");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230589");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230591");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230592");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230699");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230700");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230701");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230702");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230703");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230705");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230706");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230707");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230709");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230710");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230711");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230712");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230719");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230724");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230725");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230730");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230731");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230732");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230733");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230747");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230748");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230751");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230752");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230756");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230761");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230766");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230767");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230768");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230771");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230772");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230776");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230783");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230786");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230791");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230794");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230796");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230802");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230806");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230808");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230810");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230812");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230813");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230814");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230815");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230821");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230825");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230830");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231013");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231017");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231116");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231120");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231146");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231180");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231181");
  script_set_attribute(attribute:"see_also", value:"https://lists.suse.com/pipermail/sle-updates/2024-October/037209.html");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48901");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48911");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48923");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48935");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48944");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48945");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52610");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52916");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26640");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26759");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26767");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26804");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26837");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-37353");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38538");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38596");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38632");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40910");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40973");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40983");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41062");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41082");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42154");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42259");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42265");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42304");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42305");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42306");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43828");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43835");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43890");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43898");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43912");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43914");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-44935");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-44944");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-44946");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-44948");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-44950");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-44952");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-44954");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-44967");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-44969");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-44970");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-44971");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-44972");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-44977");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-44982");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-44986");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-44987");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-44988");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-44989");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-44990");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-44998");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-44999");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-45000");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-45001");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-45003");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-45006");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-45007");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-45008");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-45011");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-45013");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-45015");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-45018");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-45020");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-45021");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-45026");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-45028");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-45029");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46673");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46674");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46675");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46676");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46677");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46679");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46685");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46686");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46689");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46694");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46702");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46707");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46714");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46715");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46717");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46720");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46721");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46722");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46723");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46724");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46725");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46726");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46727");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46728");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46730");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46731");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46732");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46737");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46738");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46739");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46743");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46744");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46745");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46746");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46747");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46750");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46751");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46752");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46753");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46755");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46756");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46758");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46759");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46761");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46771");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46772");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46773");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46774");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46778");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46780");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46781");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46783");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46784");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46786");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46787");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46791");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46794");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46798");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46822");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46830");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-46798");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-5_14_21-150500_13_73-rt");
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
    {'reference':'cluster-md-kmp-rt-5.14.21-150500.13.73.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'dlm-kmp-rt-5.14.21-150500.13.73.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'gfs2-kmp-rt-5.14.21-150500.13.73.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-devel-rt-5.14.21-150500.13.73.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-rt-5.14.21-150500.13.73.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-rt-devel-5.14.21-150500.13.73.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-rt-extra-5.14.21-150500.13.73.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-rt-livepatch-5.14.21-150500.13.73.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-rt-livepatch-devel-5.14.21-150500.13.73.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-rt-optional-5.14.21-150500.13.73.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-rt-vdso-5.14.21-150500.13.73.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-rt_debug-5.14.21-150500.13.73.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-rt_debug-devel-5.14.21-150500.13.73.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-rt_debug-livepatch-devel-5.14.21-150500.13.73.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-rt_debug-vdso-5.14.21-150500.13.73.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-source-rt-5.14.21-150500.13.73.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-syms-rt-5.14.21-150500.13.73.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kselftests-kmp-rt-5.14.21-150500.13.73.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'ocfs2-kmp-rt-5.14.21-150500.13.73.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'reiserfs-kmp-rt-5.14.21-150500.13.73.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-livepatch-5_14_21-150500_13_73-rt-1-150500.11.3.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.5']}
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
