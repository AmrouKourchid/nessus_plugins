#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2024:3566-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(208672);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/10");

  script_cve_id(
    "CVE-2021-4442",
    "CVE-2021-47387",
    "CVE-2021-47408",
    "CVE-2021-47620",
    "CVE-2021-47622",
    "CVE-2022-48788",
    "CVE-2022-48789",
    "CVE-2022-48790",
    "CVE-2022-48791",
    "CVE-2022-48799",
    "CVE-2022-48844",
    "CVE-2022-48911",
    "CVE-2022-48943",
    "CVE-2022-48945",
    "CVE-2023-52766",
    "CVE-2023-52915",
    "CVE-2024-27024",
    "CVE-2024-38381",
    "CVE-2024-38596",
    "CVE-2024-38632",
    "CVE-2024-40973",
    "CVE-2024-41000",
    "CVE-2024-41073",
    "CVE-2024-41079",
    "CVE-2024-41082",
    "CVE-2024-42154",
    "CVE-2024-42265",
    "CVE-2024-42305",
    "CVE-2024-42306",
    "CVE-2024-43884",
    "CVE-2024-43890",
    "CVE-2024-43898",
    "CVE-2024-43904",
    "CVE-2024-43912",
    "CVE-2024-43914",
    "CVE-2024-44946",
    "CVE-2024-44947",
    "CVE-2024-44948",
    "CVE-2024-44950",
    "CVE-2024-44952",
    "CVE-2024-44954",
    "CVE-2024-44969",
    "CVE-2024-44972",
    "CVE-2024-44982",
    "CVE-2024-44987",
    "CVE-2024-44998",
    "CVE-2024-44999",
    "CVE-2024-45008",
    "CVE-2024-46673",
    "CVE-2024-46675",
    "CVE-2024-46676",
    "CVE-2024-46677",
    "CVE-2024-46679",
    "CVE-2024-46685",
    "CVE-2024-46686",
    "CVE-2024-46702",
    "CVE-2024-46707",
    "CVE-2024-46714",
    "CVE-2024-46715",
    "CVE-2024-46717",
    "CVE-2024-46720",
    "CVE-2024-46721",
    "CVE-2024-46722",
    "CVE-2024-46723",
    "CVE-2024-46727",
    "CVE-2024-46731",
    "CVE-2024-46737",
    "CVE-2024-46738",
    "CVE-2024-46739",
    "CVE-2024-46743",
    "CVE-2024-46744",
    "CVE-2024-46745",
    "CVE-2024-46746",
    "CVE-2024-46747",
    "CVE-2024-46750",
    "CVE-2024-46753",
    "CVE-2024-46759",
    "CVE-2024-46761",
    "CVE-2024-46770",
    "CVE-2024-46772",
    "CVE-2024-46773",
    "CVE-2024-46774",
    "CVE-2024-46778",
    "CVE-2024-46783",
    "CVE-2024-46784",
    "CVE-2024-46787",
    "CVE-2024-46822",
    "CVE-2024-46853",
    "CVE-2024-46854",
    "CVE-2024-46859"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2024:3566-1");

  script_name(english:"SUSE SLES12 Security Update : kernel (SUSE-SU-2024:3566-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES12 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SUSE-SU-2024:3566-1 advisory.

    The SUSE Linux Enterprise 12 SP5 RT kernel was updated to receive various security bugfixes.


    The following security bugs were fixed:

    - CVE-2024-46854: net: dpaa: Pad packets to ETH_ZLEN (bsc#1231084).
    - CVE-2024-46770: ice: Add netif_device_attach/detach into PF reset flow (bsc#1230763).
    - CVE-2024-41073: nvme: avoid double free special payload (bsc#1228635).
    - CVE-2024-41079: nvmet: always initialize cqe.result (bsc#1228615).
    - CVE-2024-46859: platform/x86: panasonic-laptop: Fix SINF array out of bounds accesses (bsc#1231089).
    - CVE-2024-46853: spi: nxp-fspi: fix the KASAN report out-of-bounds bug (bsc#1231083).
    - CVE-2022-48945: media: vivid: fix compose size exceed boundary (bsc#1230398).
    - CVE-2024-41082: nvme-fabrics: use reserved tag for reg read/write command  (bsc#1228620 CVE-2024-41082).
    - CVE-2024-46822: arm64: acpi: Harden get_cpu_for_acpi_id() against missing CPU entry (bsc#1231120).
    - CVE-2024-43890: tracing: Fix overflow in get_free_elt() (bsc#1229764).
    - CVE-2024-46731: drm/amd/pm: fix the Out-of-bounds read warning (bsc#1230709).
    - CVE-2024-46772: drm/amd/display: Check denominator crb_pipes before used (bsc#1230772).
    - CVE-2024-46722: drm/amdgpu: fix mc_data out-of-bounds read warning (bsc#1230712).
    - CVE-2024-46787: userfaultfd: fix checks for huge PMDs (bsc#1230815).
    - CVE-2022-48911: kabi: add __nf_queue_get_refs() for kabi compliance.  (bsc#1229633).
    - CVE-2024-46753: btrfs: handle errors from btrfs_dec_ref() properly (bsc#1230796).
    - CVE-2024-46761: pci/hotplug/pnv_php: Fix hotplug driver crash on Powernv (bsc#1230761).
    - CVE-2024-46759: hwmon: (adc128d818) Fix underflows seen when writing limit attributes (bsc#1230814).
    - CVE-2024-46745: Input: uinput - reject requests with unreasonable number of slots (bsc#1230748).
    - CVE-2024-46738: VMCI: Fix use-after-free when removing resource in vmci_resource_remove() (bsc#1230731).
    - CVE-2024-46783: tcp_bpf: fix return value of tcp_bpf_sendmsg() (bsc#1230810).
    - CVE-2024-44982: drm/msm/dpu: cleanup FB if dpu_format_populate_layout fails (bsc#1230204).
    - CVE-2024-46723: drm/amdgpu: fix ucode out-of-bounds read warning (bsc#1230702).
    - CVE-2024-46750: PCI: Add missing bridge lock to pci_bus_lock() (bsc#1230783).
    - CVE-2024-46717: net/mlx5e: SHAMPO, Fix incorrect page release (bsc#1230719).
    - CVE-2024-40973: media: mtk-vcodec: potential null pointer deference in SCP (bsc#1227890).
    - CVE-2024-46744: Squashfs: sanity check symbolic link size (bsc#1230747).
    - CVE-2024-46743: of/irq: Prevent device address out-of-bounds read in interrupt map walk (bsc#1230756).
    - CVE-2024-46715: driver: iio: add missing checks on iio_info's callback access  (bsc#1230700).
    - CVE-2024-46685: pinctrl: single: fix potential NULL dereference in pcs_get_function() (bsc#1230515)
    - CVE-2024-46675: usb: dwc3: core: Prevent USB core invalid event buffer address access (bsc#1230533).
    - CVE-2024-46702: thunderbolt: Mark XDomain as unplugged when router is removed (bsc#1230589)
    - CVE-2024-46686: smb/client: avoid dereferencing rdata=NULL in smb2_new_read_req() (bsc#1230517).
    - CVE-2024-46673: scsi: aacraid: Fix double-free on probe failure (bsc#1230506).
    - CVE-2024-46721: pparmor: fix possible NULL pointer dereference (bsc#1230710)
    - CVE-2024-46677: gtp: fix a potential NULL pointer dereference (bsc#1230549).
    - CVE-2024-46676: nfc: pn533: Add poll mod list filling check (bsc#1230535).
    - CVE-2024-46679: ethtool: check device is present when getting link settings (bsc#1230556).
    - CVE-2024-43914: md/raid5: avoid BUG_ON() while continue reshape after reassembling (bsc#1229790).
    - CVE-2024-44946: kcm: Serialise kcm_sendmsg() for the same socket (bsc#1230015).
    - CVE-2024-46707: KVM: arm64: Make ICC_*SGI*_EL1 undef in the absence of a vGICv3  (bsc#1230582).
    - CVE-2022-48799: perf: Fix list corruption in perf_cgroup_switch() (bsc#1227953).
    - CVE-2022-48789: nvme-tcp: fix possible use-after-free in transport error_recovery work (bsc#1228000).
    - CVE-2022-48790: nvme: fix a possible use-after-free in controller reset during load (bsc#1227941).
    - CVE-2024-41000: block/ioctl: prefer different overflow check (bsc#1227867).
    - CVE-2024-44948: x86/mtrr: Check if fixed MTRRs exist before saving them (bsc#1230174).
    - CVE-2022-48788: nvme-rdma: fix possible use-after-free in transport error_recovery work (bsc#1227952).
    - CVE-2024-45008: Input: MT - limit max slots (bsc#1230248).
    - CVE-2024-44987: ipv6: prevent UAF in ip6_send_skb() (bsc#1230185).
    - CVE-2024-44999: gtp: pull network headers in gtp_dev_xmit() (bsc#1230233).
    - CVE-2022-48943: KVM: x86/mmu: make apf token non-zero to fix bug (bsc#1229645).
    - CVE-2023-52915: media: dvb-usb-v2: af9035: fix missing unlock (bsc#1230270).
    - CVE-2022-48844: Bluetooth: hci_core: Fix leaking sent_cmd skb (bsc#1228068).
    - CVE-2024-43912: wifi: nl80211: disallow setting special AP channel widths (bsc#1229830)
    - CVE-2022-48791: Fix use-after-free for aborted TMF sas_task (bsc#1228002)
    - CVE-2024-43898: ext4: sanity check for NULL pointer after ext4_force_shutdown (bsc#1229753).
    - CVE-2024-42306: udf: Avoid using corrupted block bitmap buffer (bsc#1229362).
    - CVE-2024-42305: ext4: check dot and dotdot of dx_root before making dir indexed (bsc#1229363).
    - CVE-2024-42265: protect the fetch of ->fd[fd] in do_dup2() from mispredictions (bsc#1229334).
    - CVE-2024-44950: serial: sc16is7xx: fix invalid FIFO access with special register set (bsc#1230180).
    - CVE-2024-27024: net/rds: fix WARNING in rds_conn_connect_if_down (bsc#1223777).
    - CVE-2024-44954: ALSA: line6: Fix racy access to midibuf (bsc#1230176).
    - CVE-2024-44998: atm: idt77252: prevent use after free in dequeue_rx() (bsc#1230171).
    - CVE-2024-44952: driver core: Fix uevent_show() vs driver detach race  (bsc#1230178).
    - CVE-2021-47387: cpufreq: schedutil: Destroy mutex before kobject_put() frees the memory (bsc#1225316).
    - CVE-2024-44969: s390/sclp: Prevent release of buffer in I/O (bsc#1230200).
    - CVE-2024-43904: Add null checks for 'stream' and 'plane' before dereferencing (bsc#1229768)
    - CVE-2024-43884: Add error handling to pair_device() (bsc#1229739)
    - CVE-2024-38596: af_unix: Fix data races in unix_release_sock/unix_stream_sendmsg (bsc#1226846).
    - CVE-2024-42154: tcp_metrics: validate source addr length (bsc#1228507).


Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1054914");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1065729");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207341");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223777");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225316");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226669");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226846");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226860");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226878");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227487");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227867");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227890");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227917");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227941");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227952");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227953");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228000");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228002");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228068");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228507");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228615");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228620");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228635");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229334");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229362");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229363");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229456");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229457");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229633");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229645");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229739");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229753");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229764");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229768");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229790");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229830");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229912");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230015");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230151");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230171");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230174");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230176");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230178");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230180");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230185");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230200");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230204");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230212");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230233");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230248");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230270");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230398");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230506");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230515");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230517");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230533");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230535");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230549");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230556");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230582");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230589");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230620");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230699");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230700");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230702");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230707");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230709");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230710");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230712");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230719");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230724");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230730");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230731");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230732");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230747");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230748");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230751");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230752");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230756");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230761");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230763");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230767");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230771");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230772");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230776");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230783");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230791");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230796");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230810");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230814");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230815");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230826");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231083");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231084");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231089");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231120");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231146");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231184");
  # https://lists.suse.com/pipermail/sle-security-updates/2024-October/019578.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dbc050ed");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-4442");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47387");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47408");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47620");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47622");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48788");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48789");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48790");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48791");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48799");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48844");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48911");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48943");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48945");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52766");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52915");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27024");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38381");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38596");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38632");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40973");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41000");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41073");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41079");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41082");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42154");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42265");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42305");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42306");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43884");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43890");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43898");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43904");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43912");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43914");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-44946");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-44947");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-44948");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-44950");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-44952");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-44954");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-44969");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-44972");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-44982");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-44987");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-44998");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-44999");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-45008");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46673");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46675");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46676");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46677");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46679");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46685");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46686");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46702");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46707");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46714");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46715");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46717");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46720");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46721");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46722");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46723");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46727");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46731");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46737");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46738");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46739");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46743");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46744");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46745");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46746");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46747");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46750");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46753");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46759");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46761");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46770");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46772");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46773");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46774");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46778");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46783");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46784");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46787");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46822");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46853");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46854");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46859");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-46859");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/10");

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
    {'reference':'cluster-md-kmp-rt-4.12.14-10.203.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Linux-Enterprise-RT-release-12.5']},
    {'reference':'dlm-kmp-rt-4.12.14-10.203.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Linux-Enterprise-RT-release-12.5']},
    {'reference':'gfs2-kmp-rt-4.12.14-10.203.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Linux-Enterprise-RT-release-12.5']},
    {'reference':'kernel-devel-rt-4.12.14-10.203.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Linux-Enterprise-RT-release-12.5']},
    {'reference':'kernel-rt-4.12.14-10.203.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Linux-Enterprise-RT-release-12.5']},
    {'reference':'kernel-rt-base-4.12.14-10.203.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Linux-Enterprise-RT-release-12.5']},
    {'reference':'kernel-rt-devel-4.12.14-10.203.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Linux-Enterprise-RT-release-12.5']},
    {'reference':'kernel-rt_debug-4.12.14-10.203.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Linux-Enterprise-RT-release-12.5']},
    {'reference':'kernel-rt_debug-devel-4.12.14-10.203.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Linux-Enterprise-RT-release-12.5']},
    {'reference':'kernel-source-rt-4.12.14-10.203.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Linux-Enterprise-RT-release-12.5']},
    {'reference':'kernel-syms-rt-4.12.14-10.203.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Linux-Enterprise-RT-release-12.5']},
    {'reference':'ocfs2-kmp-rt-4.12.14-10.203.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Linux-Enterprise-RT-release-12.5']}
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
