#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2024-12815.
##

include('compat.inc');

if (description)
{
  script_id(210893);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/13");

  script_cve_id(
    "CVE-2023-31083",
    "CVE-2023-52450",
    "CVE-2024-26585",
    "CVE-2024-26987",
    "CVE-2024-36028",
    "CVE-2024-38538",
    "CVE-2024-38577",
    "CVE-2024-39472",
    "CVE-2024-39483",
    "CVE-2024-41009",
    "CVE-2024-41011",
    "CVE-2024-41012",
    "CVE-2024-41015",
    "CVE-2024-41017",
    "CVE-2024-41019",
    "CVE-2024-41020",
    "CVE-2024-41042",
    "CVE-2024-41059",
    "CVE-2024-41060",
    "CVE-2024-41063",
    "CVE-2024-41064",
    "CVE-2024-41065",
    "CVE-2024-41068",
    "CVE-2024-41070",
    "CVE-2024-41072",
    "CVE-2024-41073",
    "CVE-2024-41077",
    "CVE-2024-41078",
    "CVE-2024-41081",
    "CVE-2024-41090",
    "CVE-2024-41091",
    "CVE-2024-41098",
    "CVE-2024-42114",
    "CVE-2024-42126",
    "CVE-2024-42228",
    "CVE-2024-42259",
    "CVE-2024-42265",
    "CVE-2024-42267",
    "CVE-2024-42271",
    "CVE-2024-42276",
    "CVE-2024-42277",
    "CVE-2024-42280",
    "CVE-2024-42281",
    "CVE-2024-42283",
    "CVE-2024-42284",
    "CVE-2024-42285",
    "CVE-2024-42290",
    "CVE-2024-42291",
    "CVE-2024-42292",
    "CVE-2024-42295",
    "CVE-2024-42296",
    "CVE-2024-42297",
    "CVE-2024-42299",
    "CVE-2024-42301",
    "CVE-2024-42302",
    "CVE-2024-42304",
    "CVE-2024-42305",
    "CVE-2024-42306",
    "CVE-2024-42308",
    "CVE-2024-42309",
    "CVE-2024-42310",
    "CVE-2024-42311",
    "CVE-2024-42312",
    "CVE-2024-42313",
    "CVE-2024-42318",
    "CVE-2024-43817",
    "CVE-2024-43821",
    "CVE-2024-43829",
    "CVE-2024-43830",
    "CVE-2024-43834",
    "CVE-2024-43835",
    "CVE-2024-43839",
    "CVE-2024-43841",
    "CVE-2024-43846",
    "CVE-2024-43849",
    "CVE-2024-43853",
    "CVE-2024-43854",
    "CVE-2024-43856",
    "CVE-2024-43858",
    "CVE-2024-43860",
    "CVE-2024-43861",
    "CVE-2024-43863",
    "CVE-2024-43867",
    "CVE-2024-43870",
    "CVE-2024-43871",
    "CVE-2024-43873",
    "CVE-2024-43875",
    "CVE-2024-43879",
    "CVE-2024-43880",
    "CVE-2024-43882",
    "CVE-2024-43883",
    "CVE-2024-43884",
    "CVE-2024-43885",
    "CVE-2024-43889",
    "CVE-2024-43890",
    "CVE-2024-43892",
    "CVE-2024-43893",
    "CVE-2024-43894",
    "CVE-2024-43897",
    "CVE-2024-43902",
    "CVE-2024-43905",
    "CVE-2024-43907",
    "CVE-2024-43908",
    "CVE-2024-43909",
    "CVE-2024-43914",
    "CVE-2024-44934",
    "CVE-2024-44935",
    "CVE-2024-44944",
    "CVE-2024-44946",
    "CVE-2024-44947",
    "CVE-2024-44948",
    "CVE-2024-44954",
    "CVE-2024-44958",
    "CVE-2024-44960",
    "CVE-2024-44965",
    "CVE-2024-44966",
    "CVE-2024-44968",
    "CVE-2024-44969",
    "CVE-2024-44971",
    "CVE-2024-44982",
    "CVE-2024-44983",
    "CVE-2024-44985",
    "CVE-2024-44986",
    "CVE-2024-44987",
    "CVE-2024-44988",
    "CVE-2024-44989",
    "CVE-2024-44990",
    "CVE-2024-44995",
    "CVE-2024-44998",
    "CVE-2024-44999",
    "CVE-2024-45003",
    "CVE-2024-45006",
    "CVE-2024-45007",
    "CVE-2024-45008",
    "CVE-2024-45011",
    "CVE-2024-45016",
    "CVE-2024-45018",
    "CVE-2024-45021",
    "CVE-2024-45025",
    "CVE-2024-45026",
    "CVE-2024-45028",
    "CVE-2024-46673",
    "CVE-2024-46674",
    "CVE-2024-46675",
    "CVE-2024-46676",
    "CVE-2024-46677",
    "CVE-2024-46679",
    "CVE-2024-46685",
    "CVE-2024-46702",
    "CVE-2024-46707",
    "CVE-2024-46713",
    "CVE-2024-46714",
    "CVE-2024-46719",
    "CVE-2024-46721",
    "CVE-2024-46722",
    "CVE-2024-46723",
    "CVE-2024-46724",
    "CVE-2024-46725",
    "CVE-2024-46731",
    "CVE-2024-46732",
    "CVE-2024-46734",
    "CVE-2024-46737",
    "CVE-2024-46739",
    "CVE-2024-46740",
    "CVE-2024-46743",
    "CVE-2024-46744",
    "CVE-2024-46745",
    "CVE-2024-46746",
    "CVE-2024-46747",
    "CVE-2024-46750",
    "CVE-2024-46752",
    "CVE-2024-46755",
    "CVE-2024-46756",
    "CVE-2024-46757",
    "CVE-2024-46758",
    "CVE-2024-46759",
    "CVE-2024-46761",
    "CVE-2024-46763",
    "CVE-2024-46771",
    "CVE-2024-46777",
    "CVE-2024-46780",
    "CVE-2024-46781",
    "CVE-2024-46782",
    "CVE-2024-46783",
    "CVE-2024-46791",
    "CVE-2024-46795",
    "CVE-2024-46798",
    "CVE-2024-46800",
    "CVE-2024-46804",
    "CVE-2024-46805",
    "CVE-2024-46807",
    "CVE-2024-46810",
    "CVE-2024-46814",
    "CVE-2024-46815",
    "CVE-2024-46817",
    "CVE-2024-46818",
    "CVE-2024-46819",
    "CVE-2024-46822",
    "CVE-2024-46828",
    "CVE-2024-46829",
    "CVE-2024-46832",
    "CVE-2024-46839",
    "CVE-2024-46840",
    "CVE-2024-46844",
    "CVE-2024-47663",
    "CVE-2024-47665",
    "CVE-2024-47667",
    "CVE-2024-47668",
    "CVE-2024-47669",
    "CVE-2024-47674",
    "CVE-2024-49863"
  );

  script_name(english:"Oracle Linux 8 / 9 : Unbreakable Enterprise kernel (ELSA-2024-12815)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 8 / 9 host has packages installed that are affected by multiple vulnerabilities as referenced in
the ELSA-2024-12815 advisory.

    - ice: Add a per-VF limit on number of FDIR filters (Ahmed Zaki)  [Orabug: 36964088]  {CVE-2024-42291}
    - scsi: lpfc: Fix a possible null pointer dereference (Huai-Yuan Liu)  [Orabug: 36964437]
    {CVE-2024-43821}
    - perf/x86/intel/uncore: Fix NULL pointer dereference issue in upi_fill_topology() (Alexander Antonov)
    [Orabug: 36882937]  {CVE-2023-52450}
    - memcg: protect concurrent access to mem_cgroup_idr (Shakeel Butt) [Orabug: 36993003] {CVE-2024-43892}
    - btrfs: fix race between direct IO write and fsync when using same fd (Filipe Manana) [Orabug: 37195092]
    {CVE-2024-46734}
    - net: drop bad gso csum_start and offset in virtio_net_hdr (Willem de Bruijn) [Orabug: 37195028]
    {CVE-2024-43897}
    - nvmet-tcp: fix kernel crash if commands allocation fails (Maurizio Lombardi) [Orabug: 37074464]
    {CVE-2024-46737}
    - arm64: acpi: Harden get_cpu_for_acpi_id() against missing CPU entry (Jonathan Cameron) [Orabug:
    37116411] {CVE-2024-46822}
    - workqueue: Improve scalability of workqueue watchdog touch (Nicholas Piggin) [Orabug: 37116487]
    {CVE-2024-46839}
    - nilfs2: protect references to superblock parameters exposed in sysfs (Ryusuke Konishi) [Orabug:
    37074676] {CVE-2024-46780}
    - ksmbd: unset the binding mark of a reused connection (Namjae Jeon) [Orabug: 37074716] {CVE-2024-46795}
    - perf/aux: Fix AUX buffer serialization (Peter Zijlstra) [Orabug: 37070802] {CVE-2024-46713}
    - uio_hv_generic: Fix kernel NULL pointer dereference in hv_uio_rescind (Saurabh Sengar) [Orabug:
    37074472] {CVE-2024-46739}
    - binder: fix UAF caused by offsets overwrite (Carlos Llamas) [Orabug: 37074476] {CVE-2024-46740}
    - staging: iio: frequency: ad9834: Validate frequency parameter value (Aleksandr Mishin) [Orabug:
    37159727] {CVE-2024-47663}
    - MIPS: cevt-r4k: Don't call get_c0_compare_int if timer irq is installed (Jiaxun Yang) [Orabug: 37116454]
    {CVE-2024-46832}
    - lib/generic-radix-tree.c: Fix rare race in __genradix_ptr_alloc() (Kent Overstreet) [Orabug: 37159756]
    {CVE-2024-47668}
    - of/irq: Prevent device address out-of-bounds read in interrupt map walk (Stefan Wiehler) [Orabug:
    37074487] {CVE-2024-46743}
    - Squashfs: sanity check symbolic link size (Phillip Lougher) [Orabug: 37074494] {CVE-2024-46744}
    - Input: uinput - reject requests with unreasonable number of slots (Dmitry Torokhov) [Orabug: 37074502]
    {CVE-2024-46745}
    - HID: amd_sfh: free driver_data after destroying hid device (Olivier Sobrie) [Orabug: 37074507]
    {CVE-2024-46746}
    - HID: cougar: fix slab-out-of-bounds Read in cougar_report_fixup (Camila Alvarez) [Orabug: 37074512]
    {CVE-2024-46747}
    - i3c: mipi-i3c-hci: Error out instead on BUG_ON() in IBI DMA setup (Jarkko Nikula) [Orabug: 37159737]
    {CVE-2024-47665}
    - PCI: Add missing bridge lock to pci_bus_lock() (Dan Williams) [Orabug: 37074530] {CVE-2024-46750}
    - btrfs: replace BUG_ON() with error handling at update_ref_for_cow() (Filipe Manana) [Orabug: 37074542]
    {CVE-2024-46752}
    - btrfs: clean up our handling of refs == 0 in snapshot delete (Josef Bacik) [Orabug: 37116493]
    {CVE-2024-46840}
    - wifi: mwifiex: Do not return unused priv in mwifiex_get_priv_by_id() (Sascha Hauer) [Orabug: 37074560]
    {CVE-2024-46755}
    - hwmon: (w83627ehf) Fix underflows seen when writing limit attributes (Guenter Roeck) [Orabug: 37074565]
    {CVE-2024-46756}
    - hwmon: (nct6775-core) Fix underflows seen when writing limit attributes (Guenter Roeck) [Orabug:
    37074570] {CVE-2024-46757}
    - hwmon: (lm95234) Fix underflows seen when writing limit attributes (Guenter Roeck) [Orabug: 37074578]
    {CVE-2024-46758}
    - hwmon: (adc128d818) Fix underflows seen when writing limit attributes (Guenter Roeck) [Orabug: 37074583]
    {CVE-2024-46759}
    - pci/hotplug/pnv_php: Fix hotplug driver crash on Powernv (Krishna Kumar) [Orabug: 37074594]
    {CVE-2024-46761}
    - um: line: always fill *error_out in setup_one_line() (Johannes Berg) [Orabug: 37116517] {CVE-2024-46844}
    - fou: Fix null-ptr-deref in GRO. (Kuniyuki Iwashima) [Orabug: 37074606] {CVE-2024-46763}
    - tcp_bpf: fix return value of tcp_bpf_sendmsg() (Cong Wang) [Orabug: 37074692] {CVE-2024-46783}
    - can: bcm: Remove proc entry when dev is unregistered. (Kuniyuki Iwashima) [Orabug: 37074624]
    {CVE-2024-46771}
    - PCI: keystone: Add workaround for Errata #i2037 (AM65x SR 1.0) (Kishon Vijay Abraham I) [Orabug:
    37159749] {CVE-2024-47667}
    - udf: Avoid excessive partition lengths (Jan Kara) [Orabug: 37074664] {CVE-2024-46777}
    - nilfs2: fix state management in error path of log writing function (Ryusuke Konishi) [Orabug: 37159764]
    {CVE-2024-47669}
    - nilfs2: fix missing cleanup on rollforward recovery error (Ryusuke Konishi) [Orabug: 37074683]
    {CVE-2024-46781}
    - sched: sch_cake: fix bulk flow accounting logic for host fairness (Toke Hoiland-Jorgensen) [Orabug:
    37116442] {CVE-2024-46828}
    - ila: call nf_unregister_net_hooks() sooner (Eric Dumazet) [Orabug: 37074688] {CVE-2024-46782}
    - can: mcp251x: fix deadlock if an interrupt occurs during mcp251x_open (Simon Arlott) [Orabug: 37074711]
    {CVE-2024-46791}
    - rtmutex: Drop rt_mutex::wait_lock before scheduling (Roland Xu) [Orabug: 37116445] {CVE-2024-46829}
    - ASoC: dapm: Fix UAF for snd_soc_pcm_runtime object (robelin) [Orabug: 37074721] {CVE-2024-46798}
    - sch/netem: fix use after free in netem_dequeue (Stephen Hemminger) [Orabug: 37074725] {CVE-2024-46800}
    - rcu-tasks: Fix show_rcu_tasks_trace_gp_kthread buffer overflow (Nikita Kiryushin) [Orabug: 36753533]
    {CVE-2024-38577}
    - virtio_net: Fix napi_skb_cache_put warning (Breno Leitao) [Orabug: 36964473] {CVE-2024-43835}
    - drm/amd/pm: Fix the null pointer dereference for vega10_hwmgr (Bob Zhou) [Orabug: 36993065]
    {CVE-2024-43905}
    - drm/amd/display: Skip wbscl_set_scaler_filter if filter is null (Alex Hung) [Orabug: 37073031]
    {CVE-2024-46714}
    - drm/bridge: tc358767: Check if fully initialized before signalling HPD event via IRQ (Marek Vasut)
    [Orabug: 37116336] {CVE-2024-46810}
    - usb: typec: ucsi: Fix null pointer dereference in trace (Abhishek Pandit-Subedi) [Orabug: 37073064]
    {CVE-2024-46719}
    - drm/amdgpu: the warning dereferencing obj for nbio_v7_4 (Jesse Zhang) [Orabug: 37116393]
    {CVE-2024-46819}
    - drm/amdgpu: fix the waring dereferencing hive (Jesse Zhang) [Orabug: 37116300] {CVE-2024-46805}
    - apparmor: fix possible NULL pointer dereference (Leesoo Ahn) [Orabug: 37073077] {CVE-2024-46721}
    - drm/amdgpu: fix mc_data out-of-bounds read warning (Tim Huang) [Orabug: 37073082] {CVE-2024-46722}
    - drm/amdgpu: fix ucode out-of-bounds read warning (Tim Huang) [Orabug: 37073087] {CVE-2024-46723}
    - drm/amdgpu: Fix out-of-bounds read of df_v1_7_channel_number (Ma Jun) [Orabug: 37073093]
    {CVE-2024-46724}
    - drm/amdgpu: Fix out-of-bounds write warning (Ma Jun) [Orabug: 37073098] {CVE-2024-46725}
    - drm/amd/amdgpu: Check tbo resource pointer (Asad Kamal) [Orabug: 37116315] {CVE-2024-46807}
    - drm/amd/display: Check msg_id before processing transcation (Alex Hung) [Orabug: 37116360]
    {CVE-2024-46814}
    - drm/amd/display: Check num_valid_sets before accessing reader_wm_sets[] (Alex Hung) [Orabug: 37116365]
    {CVE-2024-46815}
    - drm/amd/display: Add array index check for hdcp ddc access (Hersen Wu) [Orabug: 37116295]
    {CVE-2024-46804}
    - drm/amd/display: Stop amdgpu_dm initialize when stream nums greater than 6 (Hersen Wu) [Orabug:
    37116375] {CVE-2024-46817}
    - drm/amd/display: Check gpio_id before used as array index (Alex Hung) [Orabug: 37116384]
    {CVE-2024-46818}
    - drm/amd/pm: fix the Out-of-bounds read warning (Jesse Zhang) [Orabug: 37073129] {CVE-2024-46731}
    - drm/amd/display: Assign linear_pitch_alignment even for VM (Alvin Lee) [Orabug: 37073135]
    {CVE-2024-46732}
    - scsi: aacraid: Fix double-free on probe failure (Ben Hutchings) [Orabug: 37070699] {CVE-2024-46673}
    - usb: dwc3: st: fix probed platform device ref count on probe error path (Krzysztof Kozlowski) [Orabug:
    37070704] {CVE-2024-46674}
    - usb: dwc3: core: Prevent USB core invalid event buffer address access (Selvarasu Ganesan) [Orabug:
    37070709] {CVE-2024-46675}
    - nfc: pn533: Add poll mod list filling check (Aleksandr Mishin) [Orabug: 37070716] {CVE-2024-46676}
    - gtp: fix a potential NULL pointer dereference (Cong Wang) [Orabug: 37070721] {CVE-2024-46677}
    - ethtool: check device is present when getting link settings (Jamie Bainbridge) [Orabug: 37070727]
    {CVE-2024-46679}
    - cgroup/cpuset: Prevent UAF in proc_cpuset_show() (Chen Ridong) [Orabug: 36964509] {CVE-2024-43853}
    - ata: libata-core: Fix null pointer dereference on error (Niklas Cassel) [Orabug: 36897456]
    {CVE-2024-41098}
    - drm/amdkfd: don't allow mapping the MMIO HDP page with large pages (Alex Deucher) [Orabug: 36867630]
    {CVE-2024-41011}
    - pinctrl: single: fix potential NULL dereference in pcs_get_function() (Ma Ke) [Orabug: 37070743]
    {CVE-2024-46685}
    - drm/amdgpu: Using uninitialized value *size when calling amdgpu_vce_cs_reloc (Jesse Zhang) [Orabug:
    36898008] {CVE-2024-42228}
    (Alexander Lobakin)
    - Input: MT - limit max slots (Tetsuo Handa) [Orabug: 37029136] {CVE-2024-45008}
    - Bluetooth: hci_ldisc: check HCI_UART_PROTO_READY flag in HCIUARTGETPROTO (Lee, Chun-Yi) [Orabug:
    35358656] {CVE-2023-31083}
    - KVM: arm64: Make ICC_*SGI*_EL1 undef in the absence of a vGICv3 (Marc Zyngier) [Orabug: 37070792]
    {CVE-2024-46707}
    - Bluetooth: MGMT: Add error handling to pair_device() (Griffin Kroah-Hartman) [Orabug: 36992975]
    {CVE-2024-43884}
    - mmc: mmc_test: Fix NULL dereference on allocation failure (Dan Carpenter) [Orabug: 37070690]
    {CVE-2024-45028}
    - drm/msm/dpu: cleanup FB if dpu_format_populate_layout fails (Dmitry Baryshkov) [Orabug: 37029059]
    {CVE-2024-44982}
    - netfilter: flowtable: validate vlan header (Pablo Neira Ayuso) [Orabug: 37029063] {CVE-2024-44983}
    - ipv6: prevent possible UAF in ip6_xmit() (Eric Dumazet) [Orabug: 37029066] {CVE-2024-44985}
    - ipv6: fix possible UAF in ip6_finish_output2() (Eric Dumazet) [Orabug: 37029068] {CVE-2024-44986}
    - ipv6: prevent UAF in ip6_send_skb() (Eric Dumazet) [Orabug: 37029075] {CVE-2024-44987}
    - netem: fix return value if duplicate enqueue fails (Stephen Hemminger) [Orabug: 37070659]
    {CVE-2024-45016}
    - net: dsa: mv88e6xxx: Fix out-of-bound access (Joseph Huang) [Orabug: 37029081] {CVE-2024-44988}
    - bonding: fix xfrm real_dev null pointer dereference (Nikolay Aleksandrov) [Orabug: 37029084]
    {CVE-2024-44989}
    - bonding: fix null pointer deref in bond_ipsec_offload_ok (Nikolay Aleksandrov) [Orabug: 37029087]
    {CVE-2024-44990}
    - kcm: Serialise kcm_sendmsg() for the same socket. (Kuniyuki Iwashima) [Orabug: 37013760]
    {CVE-2024-44946}
    - gtp: pull network headers in gtp_dev_xmit() (Eric Dumazet) [Orabug: 37029110] {CVE-2024-44999}
    - net: hns3: fix a deadlock problem when config TC during resetting (Jie Wang) [Orabug: 37029097]
    {CVE-2024-44995}
    - netfilter: flowtable: initialise extack before use (Donald Hunter) [Orabug: 37070666] {CVE-2024-45018}
    - atm: idt77252: prevent use after free in dequeue_rx() (Dan Carpenter) [Orabug: 37029103]
    {CVE-2024-44998}
    - memcg_write_event_control(): fix a user-triggerable oops (Al Viro) [Orabug: 37070671] {CVE-2024-45021}
    - fix bitmap corruption on close_range() with CLOSE_RANGE_UNSHARE (Al Viro) [Orabug: 37070679]
    {CVE-2024-45025}
    - vfs: Don't evict inode under the inode lru traversing context (Zhihao Cheng) [Orabug: 37029118]
    {CVE-2024-45003}
    - s390/dasd: fix error recovery leading to data corruption on ESE devices (Stefan Haberland) [Orabug:
    37070686] {CVE-2024-45026}
    - thunderbolt: Mark XDomain as unplugged when router is removed (Mika Westerberg) [Orabug: 37070774]
    {CVE-2024-46702}
    - xhci: Fix Panther point NULL pointer deref at full-speed re-enumeration (Mathias Nyman) [Orabug:
    37029124] {CVE-2024-45006}
    - char: xillybus: Check USB endpoints when probing device (Eli Billauer) [Orabug: 37070649]
    {CVE-2024-45011}
    - char: xillybus: Don't destroy workqueue from work item running on it (Eli Billauer) [Orabug: 37029128]
    {CVE-2024-45007}
    - fuse: Initialize beyond-EOF page contents before setting uptodate (Jann Horn) [Orabug: 37017950]
    {CVE-2024-44947}
    - wifi: cfg80211: restrict NL80211_ATTR_TXQ_QUANTUM values (Eric Dumazet) [Orabug: 36897690]
    {CVE-2024-42114}
    - binfmt_flat: Fix corruption when not offsetting data start (Kees Cook) [Orabug: 37029015]
    {CVE-2024-44966}
    - exec: Fix ToCToU between perm check and set-uid/gid usage (Kees Cook) [Orabug: 36984016]
    {CVE-2024-43882}
    - powerpc: Avoid nmi_enter/nmi_exit in real mode interrupt. (Mahesh Salgaonkar) [Orabug: 36897773]
    {CVE-2024-42126}
    - drm/i915/gem: Fix Virtual Memory mapping boundaries calculation (Andi Shyti) [Orabug: 36953968]
    {CVE-2024-42259}
    - netfilter: nf_tables: prefer nft_chain_validate (Florian Westphal) [Orabug: 36896845] {CVE-2024-41042}
    - tls: fix race between tx work scheduling and socket close (Jakub Kicinski) [Orabug: 36529710]
    {CVE-2024-26585}
    - PCI/DPC: Fix use-after-free on concurrent DPC and hot-removal (Lukas Wunner) [Orabug: 36964228]
    {CVE-2024-42302}
    - btrfs: fix double inode unlock for direct IO sync writes (Filipe Manana) [Orabug: 37195039]
    {CVE-2024-43885}
    - xfs: fix log recovery buffer allocation for the legacy h_size fixup (Christoph Hellwig) [Orabug:
    36809257] {CVE-2024-39472}
    - sched/smt: Fix unbalance sched_smt_present dec/inc (Yang Yingliang) [Orabug: 37028981] {CVE-2024-44958}
    - x86/mtrr: Check if fixed MTRRs exist before saving them (Andi Kleen) [Orabug: 37028935] {CVE-2024-44948}
    - padata: Fix possible divide-by-0 panic in padata_mt_helper() (Waiman Long) [Orabug: 36992992]
    {CVE-2024-43889}
    - tracing: Fix overflow in get_free_elt() (Tze-nan Wu) [Orabug: 36992997] {CVE-2024-43890}
    - serial: core: check uartclk for zero to avoid divide by zero (George Kennedy) [Orabug: 36993008]
    {CVE-2024-43893}
    - tick/broadcast: Move per CPU pointer access into the atomic section (Thomas Gleixner) [Orabug: 37195086]
    {CVE-2024-44968}
    - usb: gadget: core: Check for unset descriptor (Chris Wulff) [Orabug: 37028987] {CVE-2024-44960}
    - usb: vhci-hcd: Do not drop references before new references are gained (Oliver Neukum) [Orabug:
    36992970] {CVE-2024-43883}
    - ALSA: line6: Fix racy access to midibuf (Takashi Iwai) [Orabug: 37028956] {CVE-2024-44954}
    - drm/client: fix null pointer dereference in drm_client_modeset_probe (Ma Ke) [Orabug: 36993013]
    {CVE-2024-43894}
    - s390/sclp: Prevent release of buffer in I/O (Peter Oberparleiter) [Orabug: 37029019] {CVE-2024-44969}
    - drm/amd/display: Add null checker before passing variables (Alex Hung) [Orabug: 36993047]
    {CVE-2024-43902}
    - drm/amdgpu/pm: Fix the null pointer dereference in apply_state_adjust_rules (Ma Jun) [Orabug: 36993077]
    {CVE-2024-43907}
    - drm/amdgpu: Fix the null pointer dereference to ras_manager (Ma Jun) [Orabug: 36993083] {CVE-2024-43908}
    - drm/amdgpu/pm: Fix the null pointer dereference for smu7 (Ma Jun) [Orabug: 36993089] {CVE-2024-43909}
    - md/raid5: avoid BUG_ON() while continue reshape after reassembling (Yu Kuai) [Orabug: 36993126]
    {CVE-2024-43914}
    - net: dsa: bcm_sf2: Fix a possible memory leak in bcm_sf2_mdio_register() (Joe Hattori) [Orabug:
    37029031] {CVE-2024-44971}
    - net: bridge: mcast: wait for previous gc cycles when removing port (Nikolay Aleksandrov) [Orabug:
    36993143] {CVE-2024-44934}
    - net: usb: qmi_wwan: fix memory leak for not ip packets (Daniele Palmas) [Orabug: 36983958]
    {CVE-2024-43861}
    - sctp: Fix null-ptr-deref in reuseport_add_sock(). (Kuniyuki Iwashima) [Orabug: 36993146]
    {CVE-2024-44935}
    - x86/mm: Fix pti_clone_pgtable() alignment assumption (Peter Zijlstra) [Orabug: 37029011]
    {CVE-2024-44965}
    - drm/vmwgfx: Fix a deadlock in dma buf fence polling (Zack Rusin) [Orabug: 36983964] {CVE-2024-43863}
    - protect the fetch of ->fd[fd] in do_dup2() from mispredictions (Al Viro) [Orabug: 36963807]
    {CVE-2024-42265}
    - riscv/mm: Add handling for VM_FAULT_SIGSEGV in mm_fault_error() (Zhe Qiao) [Orabug: 36963814]
    {CVE-2024-42267}
    - net/iucv: fix use after free in iucv_sock_close() (Alexandra Winter) [Orabug: 36964005] {CVE-2024-42271}
    - drm/nouveau: prime: fix refcount underflow (Danilo Krummrich) [Orabug: 36983978] {CVE-2024-43867}
    - irqchip/imx-irqsteer: Handle runtime power management correctly (Shenwei Wang) [Orabug: 36964084]
    {CVE-2024-42290}
    - sysctl: always initialize i_uid/i_gid (Thomas Weissschuh) [Orabug: 36964269] {CVE-2024-42312}
    - nvme-pci: add missing condition check for existence of mapped data (Leon Romanovsky) [Orabug: 36964021]
    {CVE-2024-42276}
    - iommu: sprd: Avoid NULL deref in sprd_iommu_hw_en (Artem Chernyshev) [Orabug: 36964025] {CVE-2024-42277}
    - mISDN: Fix a use after free in hfcmulti_tx() (Dan Carpenter) [Orabug: 36964031] {CVE-2024-42280}
    - bpf: Fix a segment issue when downgrading gso_size (Fred Li) [Orabug: 36964037] {CVE-2024-42281}
    - net: nexthop: Initialize all fields in dumped nexthops (Petr Machata) [Orabug: 36964043]
    {CVE-2024-42283}
    - tipc: Return non-zero value from tipc_udp_addr2str() on error (Shigeru Yoshida) [Orabug: 36964046]
    {CVE-2024-42284}
    - dma: fix call order in dmam_free_coherent (Lance Richardson) [Orabug: 36964522] {CVE-2024-43856}
    - jfs: Fix array-index-out-of-bounds in diFree (Jeongjun Park) [Orabug: 36964529] {CVE-2024-43858}
    - nilfs2: handle inconsistent state in nilfs_btnode_create_block() (Ryusuke Konishi) [Orabug: 36964202]
    {CVE-2024-42295}
    - remoteproc: imx_rproc: Skip over memory region when node value is NULL (Aleksandr Mishin) [Orabug:
    36964536] {CVE-2024-43860}
    - RDMA/iwcm: Fix a use-after-free related to destroying CM IDs (Bart Van Assche) [Orabug: 36964053]
    {CVE-2024-42285}
    - perf: Fix event leak upon exit (Frederic Weisbecker) [Orabug: 36983986] {CVE-2024-43870}
    - devres: Fix memory leakage caused by driver API devm_free_percpu() (Zijun Hu) [Orabug: 36983990]
    {CVE-2024-43871}
    - kobject_uevent: Fix OOB access within zap_modalias_env() (Zijun Hu) [Orabug: 37203371] {CVE-2024-42292}
    - fs/ntfs3: Update log->page_{mask,bits} if log->page_size changed (Huacai Chen) [Orabug: 36964218]
    {CVE-2024-42299}
    - dev/parport: fix the array out-of-bounds risk (tuhaowen) [Orabug: 36964222] {CVE-2024-42301}
    - ext4: make sure the first directory block is not a hole (Baokun Li) [Orabug: 36964231] {CVE-2024-42304}
    - ext4: check dot and dotdot of dx_root before making dir indexed (Baokun Li) [Orabug: 36964236]
    {CVE-2024-42305}
    - udf: Avoid using corrupted block bitmap buffer (Jan Kara) [Orabug: 36964241] {CVE-2024-42306}
    - drm/amd/display: Check for NULL pointer (Sung Joon Kim) [Orabug: 36964246] {CVE-2024-42308}
    - drm/gma500: fix null pointer dereference in psb_intel_lvds_get_modes (Ma Ke) [Orabug: 36964252]
    {CVE-2024-42309}
    - drm/gma500: fix null pointer dereference in cdv_intel_lvds_get_modes (Ma Ke) [Orabug: 36964258]
    {CVE-2024-42310}
    - hfs: fix to initialize fields of hfs_inode_info after hfs_alloc_inode() (Chao Yu) [Orabug: 36964264]
    {CVE-2024-42311}
    - media: venus: fix use after free in vdec_close (Dikshita Agarwal) [Orabug: 36964274] {CVE-2024-42313}
    - landlock: Don't lose track of restrictions on cred_transfer (Jann Horn) [Orabug: 36964283]
    {CVE-2024-42318}
    - netfilter: ctnetlink: use helper function to calculate expect ID (Pablo Neira Ayuso) [Orabug: 37013754]
    {CVE-2024-44944}
    - net: missing check virtio (Denis Arefev) [Orabug: 36964424] {CVE-2024-43817}
    - vhost/vsock: always initialize seqpacket_allow (Michael S. Tsirkin) [Orabug: 36983999] {CVE-2024-43873}
    - PCI: endpoint: Clean up error handling in vpci_scan_bus() (Dan Carpenter) [Orabug: 36984004]
    {CVE-2024-43875}
    - drm/qxl: Add check for drm_cvt_mode (Chen Ni) [Orabug: 36964455] {CVE-2024-43829}
    - leds: trigger: Unregister sysfs attributes before calling deactivate() (Hans de Goede) [Orabug:
    36964458] {CVE-2024-43830}
    - xdp: fix invalid wait context of page_pool_destroy() (Taehee Yoo) [Orabug: 36964469] {CVE-2024-43834}
    - bna: adjust 'name' buf size of bna_tcb and bna_ccb structures (Alexey Kodanev) [Orabug: 36964479]
    {CVE-2024-43839}
    - wifi: virt_wifi: avoid reporting connection success with wrong SSID (En-Wei Wu) [Orabug: 36964486]
    {CVE-2024-43841}
    - wifi: cfg80211: handle 2x996 RU allocation in cfg80211_calculate_bitrate_he() (Baochen Qiang) [Orabug:
    36984009] {CVE-2024-43879}
    - mlxsw: spectrum_acl_erp: Fix object nesting warning (Ido Schimmel) [Orabug: 36984012] {CVE-2024-43880}
    - lib: objagg: Fix general protection fault (Ido Schimmel) [Orabug: 36964494] {CVE-2024-43846}
    - soc: qcom: pdr: protect locator_addr with the main mutex (Dmitry Baryshkov) [Orabug: 36964502]
    {CVE-2024-43849}
    - block: initialize integrity buffer to zero before writing it to media (Christoph Hellwig) [Orabug:
    36964514] {CVE-2024-43854}
    - f2fs: fix to don't dirty inode for readonly filesystem (Chao Yu) [Orabug: 36964212] {CVE-2024-42297}
    - f2fs: fix return value of f2fs_convert_inline_inode() (Chao Yu) [Orabug: 36964207] {CVE-2024-42296}
    - tap: add missing verification for short frame (Si-Wei Liu)   [Orabug: 36879156] {CVE-2024-41090}
    - tun: add missing verification for short frame (Dongli Zhang)   [Orabug: 36879156] {CVE-2024-41091}
    - filelock: Fix fcntl/close race recovery compat path (Jann Horn) [Orabug: 36874755] {CVE-2024-41012}
    {CVE-2024-41020}
    - fs/ntfs3: Validate ff offset (lei lu) [Orabug: 36891672] {CVE-2024-41019}
    - jfs: don't walk off the end of ealist (lei lu) [Orabug: 36891666] {CVE-2024-41017}
    - ocfs2: add bounds checking to ocfs2_check_dir_entry() (lei lu) [Orabug: 36891654] {CVE-2024-41015}
    - hfsplus: fix uninit-value in copy_name (Edward Adam Davis) [Orabug: 36896968] {CVE-2024-41059}
    - drm/radeon: check bo_va->bo is non-NULL before using it (Pierre-Eric Pelloux-Prayer) [Orabug: 36896974]
    {CVE-2024-41060}
    - Bluetooth: hci_core: cancel all works upon hci_unregister_dev() (Tetsuo Handa) [Orabug: 36896993]
    {CVE-2024-41063}
    - powerpc/eeh: avoid possible crash when edev->pdev changes (Ganesh Goudar) [Orabug: 36897001]
    {CVE-2024-41064}
    - powerpc/pseries: Whitelist dtl slub object for copying to userspace (Anjali K) [Orabug: 36897008]
    {CVE-2024-41065}
    - btrfs: qgroup: fix quota root leak after quota disable failure (Filipe Manana) [Orabug: 36897343]
    {CVE-2024-41078}
    - s390/sclp: Fix sclp_init() cleanup on failure (Heiko Carstens) [Orabug: 36897031] {CVE-2024-41068}
    - KVM: PPC: Book3S HV: Prevent UAF in kvm_spapr_tce_attach_iommu_group() (Michael Ellerman) [Orabug:
    36897047] {CVE-2024-41070}
    - wifi: cfg80211: wext: add extra SIOCSIWSCAN data check (Dmitry Antipov) [Orabug: 36897311]
    {CVE-2024-41072}
    - nvme: avoid double free special payload (Chunguang Xu) [Orabug: 36897316] {CVE-2024-41073}
    - null_blk: fix validation of block size (Andreas Hindborg) [Orabug: 36897338] {CVE-2024-41077}
    - ila: block BH in ila_output() (Eric Dumazet) [Orabug: 36897359] {CVE-2024-41081}
    - bpf: Fix overrunning reservations in ringbuf (Daniel Borkmann) [Orabug: 36850238] {CVE-2024-41009}
    - filelock: Remove locks reliably when fcntl/close race is detected (Jann Horn) [Orabug: 36874755]
    {CVE-2024-41012} {CVE-2024-41020}
    - mm: avoid leaving partial pfn mappings around in error case (Linus Torvalds)  [Orabug: 37174198]
    {CVE-2024-47674}
    - mm/hugetlb: fix DEBUG_LOCKS_WARN_ON(1) when dissolve_free_hugetlb_folio() (Miaohe Lin)  [Orabug:
    36683092]  {CVE-2024-36028}
    - mm/memory-failure: fix deadlock when hugetlb_optimize_vmemmap is enabled (Miaohe Lin)  [Orabug:
    36597930]  {CVE-2024-26987}
    - KVM: SVM: WARN on vNMI + NMI window iff NMIs are outright masked (Sean Christopherson)  [Orabug:
    36809298]  {CVE-2024-39483}
    - net: bridge: xmit: make sure we have at least eth header len bytes (Nikolay Aleksandrov)  [Orabug:
    36753371]  {CVE-2024-38538}
    - net: add pskb_may_pull_reason() helper (Eric Dumazet)  [Orabug: 36753371]  {CVE-2024-38538}
    - vhost/scsi: null-ptr-dereference in vhost_scsi_get_req() (Haoran Zhang)  [Orabug: 37035557]
    {CVE-2024-49863}

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2024-12815.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-46844");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:8::UEKR7");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:9::UEKR7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:9:4:baseos_patch");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:9::baseos_latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-container");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-container-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-modules-extra");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("linux_alt_patch_detect.nasl", "ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}


include('ksplice.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/OracleLinux')) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_release = get_kb_item("Host/RedHat/release");
if (isnull(os_release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:os_release)) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Oracle Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^(8|9)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 8 / 9', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var machine_uptrack_level = get_one_kb_item('Host/uptrack-uname-r');
if (machine_uptrack_level)
{
  var trimmed_uptrack_level = ereg_replace(string:machine_uptrack_level, pattern:"\.(x86_64|i[3-6]86|aarch64)$", replace:'');
  var fixed_uptrack_levels = ['5.15.0-302.167.6.el8uek', '5.15.0-302.167.6.el9uek'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2024-12815');
    }
  }
  __rpm_report = 'Running KSplice level of ' + trimmed_uptrack_level + ' does not meet the minimum fixed level of ' + join(fixed_uptrack_levels, sep:' / ') + ' for this advisory.\n\n';
}

var kernel_major_minor = get_kb_item('Host/uname/major_minor');
if (empty_or_null(kernel_major_minor)) exit(1, 'Unable to determine kernel major-minor level.');
var expected_kernel_major_minor = '5.15';
if (kernel_major_minor != expected_kernel_major_minor)
  audit(AUDIT_OS_NOT, 'running kernel level ' + expected_kernel_major_minor + ', it is running kernel level ' + kernel_major_minor);

var pkgs = [
    {'reference':'bpftool-5.15.0-302.167.6.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'bpftool-5.15.0'},
    {'reference':'kernel-uek-5.15.0-302.167.6.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-5.15.0'},
    {'reference':'kernel-uek-container-5.15.0-302.167.6.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-container-5.15.0'},
    {'reference':'kernel-uek-container-debug-5.15.0-302.167.6.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-container-debug-5.15.0'},
    {'reference':'kernel-uek-core-5.15.0-302.167.6.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-core-5.15.0'},
    {'reference':'kernel-uek-debug-5.15.0-302.167.6.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-5.15.0'},
    {'reference':'kernel-uek-debug-core-5.15.0-302.167.6.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-core-5.15.0'},
    {'reference':'kernel-uek-debug-devel-5.15.0-302.167.6.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-5.15.0'},
    {'reference':'kernel-uek-debug-modules-5.15.0-302.167.6.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-modules-5.15.0'},
    {'reference':'kernel-uek-debug-modules-extra-5.15.0-302.167.6.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-modules-extra-5.15.0'},
    {'reference':'kernel-uek-devel-5.15.0-302.167.6.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-5.15.0'},
    {'reference':'kernel-uek-doc-5.15.0-302.167.6.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-5.15.0'},
    {'reference':'kernel-uek-modules-5.15.0-302.167.6.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-modules-5.15.0'},
    {'reference':'kernel-uek-modules-extra-5.15.0-302.167.6.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-modules-extra-5.15.0'},
    {'reference':'bpftool-5.15.0-302.167.6.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'bpftool-5.15.0'},
    {'reference':'kernel-uek-5.15.0-302.167.6.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-5.15.0'},
    {'reference':'kernel-uek-container-5.15.0-302.167.6.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-container-5.15.0'},
    {'reference':'kernel-uek-container-debug-5.15.0-302.167.6.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-container-debug-5.15.0'},
    {'reference':'kernel-uek-core-5.15.0-302.167.6.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-core-5.15.0'},
    {'reference':'kernel-uek-debug-5.15.0-302.167.6.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-5.15.0'},
    {'reference':'kernel-uek-debug-core-5.15.0-302.167.6.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-core-5.15.0'},
    {'reference':'kernel-uek-debug-devel-5.15.0-302.167.6.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-5.15.0'},
    {'reference':'kernel-uek-debug-modules-5.15.0-302.167.6.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-modules-5.15.0'},
    {'reference':'kernel-uek-debug-modules-extra-5.15.0-302.167.6.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-modules-extra-5.15.0'},
    {'reference':'kernel-uek-devel-5.15.0-302.167.6.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-5.15.0'},
    {'reference':'kernel-uek-doc-5.15.0-302.167.6.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-5.15.0'},
    {'reference':'kernel-uek-modules-5.15.0-302.167.6.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-modules-5.15.0'},
    {'reference':'kernel-uek-modules-extra-5.15.0-302.167.6.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-modules-extra-5.15.0'},
    {'reference':'bpftool-5.15.0-302.167.6.el9uek', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'bpftool-5.15.0'},
    {'reference':'kernel-uek-5.15.0-302.167.6.el9uek', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-5.15.0'},
    {'reference':'kernel-uek-container-5.15.0-302.167.6.el9uek', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-container-5.15.0'},
    {'reference':'kernel-uek-container-debug-5.15.0-302.167.6.el9uek', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-container-debug-5.15.0'},
    {'reference':'kernel-uek-core-5.15.0-302.167.6.el9uek', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-core-5.15.0'},
    {'reference':'kernel-uek-debug-5.15.0-302.167.6.el9uek', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-5.15.0'},
    {'reference':'kernel-uek-debug-core-5.15.0-302.167.6.el9uek', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-core-5.15.0'},
    {'reference':'kernel-uek-debug-devel-5.15.0-302.167.6.el9uek', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-5.15.0'},
    {'reference':'kernel-uek-debug-modules-5.15.0-302.167.6.el9uek', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-modules-5.15.0'},
    {'reference':'kernel-uek-debug-modules-extra-5.15.0-302.167.6.el9uek', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-modules-extra-5.15.0'},
    {'reference':'kernel-uek-devel-5.15.0-302.167.6.el9uek', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-5.15.0'},
    {'reference':'kernel-uek-doc-5.15.0-302.167.6.el9uek', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-5.15.0'},
    {'reference':'kernel-uek-modules-5.15.0-302.167.6.el9uek', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-modules-5.15.0'},
    {'reference':'kernel-uek-modules-extra-5.15.0-302.167.6.el9uek', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-modules-extra-5.15.0'},
    {'reference':'bpftool-5.15.0-302.167.6.el9uek', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'bpftool-5.15.0'},
    {'reference':'kernel-uek-5.15.0-302.167.6.el9uek', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-5.15.0'},
    {'reference':'kernel-uek-container-5.15.0-302.167.6.el9uek', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-container-5.15.0'},
    {'reference':'kernel-uek-container-debug-5.15.0-302.167.6.el9uek', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-container-debug-5.15.0'},
    {'reference':'kernel-uek-core-5.15.0-302.167.6.el9uek', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-core-5.15.0'},
    {'reference':'kernel-uek-debug-5.15.0-302.167.6.el9uek', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-5.15.0'},
    {'reference':'kernel-uek-debug-core-5.15.0-302.167.6.el9uek', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-core-5.15.0'},
    {'reference':'kernel-uek-debug-devel-5.15.0-302.167.6.el9uek', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-5.15.0'},
    {'reference':'kernel-uek-debug-modules-5.15.0-302.167.6.el9uek', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-modules-5.15.0'},
    {'reference':'kernel-uek-debug-modules-extra-5.15.0-302.167.6.el9uek', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-modules-extra-5.15.0'},
    {'reference':'kernel-uek-devel-5.15.0-302.167.6.el9uek', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-5.15.0'},
    {'reference':'kernel-uek-doc-5.15.0-302.167.6.el9uek', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-5.15.0'},
    {'reference':'kernel-uek-modules-5.15.0-302.167.6.el9uek', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-modules-5.15.0'},
    {'reference':'kernel-uek-modules-extra-5.15.0-302.167.6.el9uek', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-modules-extra-5.15.0'}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = 'EL' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && _release) {
    if (exists_check) {
        if (rpm_exists(release:_release, rpm:exists_check) && rpm_check(release:_release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    } else {
        if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    }
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bpftool / kernel-uek / kernel-uek-container / etc');
}
