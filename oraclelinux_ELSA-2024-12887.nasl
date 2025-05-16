#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2024-12887.
##

include('compat.inc');

if (description)
{
  script_id(213191);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/18");

  script_cve_id(
    "CVE-2023-52904",
    "CVE-2024-26921",
    "CVE-2024-27017",
    "CVE-2024-27072",
    "CVE-2024-36893",
    "CVE-2024-38384",
    "CVE-2024-38545",
    "CVE-2024-38632",
    "CVE-2024-38663",
    "CVE-2024-39463",
    "CVE-2024-40953",
    "CVE-2024-41016",
    "CVE-2024-43816",
    "CVE-2024-43845",
    "CVE-2024-44931",
    "CVE-2024-45001",
    "CVE-2024-46695",
    "CVE-2024-46849",
    "CVE-2024-46852",
    "CVE-2024-46853",
    "CVE-2024-46854",
    "CVE-2024-46855",
    "CVE-2024-46858",
    "CVE-2024-46859",
    "CVE-2024-46865",
    "CVE-2024-47670",
    "CVE-2024-47671",
    "CVE-2024-47672",
    "CVE-2024-47673",
    "CVE-2024-47679",
    "CVE-2024-47684",
    "CVE-2024-47685",
    "CVE-2024-47690",
    "CVE-2024-47692",
    "CVE-2024-47693",
    "CVE-2024-47695",
    "CVE-2024-47696",
    "CVE-2024-47697",
    "CVE-2024-47698",
    "CVE-2024-47699",
    "CVE-2024-47701",
    "CVE-2024-47705",
    "CVE-2024-47709",
    "CVE-2024-47710",
    "CVE-2024-47712",
    "CVE-2024-47713",
    "CVE-2024-47718",
    "CVE-2024-47720",
    "CVE-2024-47723",
    "CVE-2024-47734",
    "CVE-2024-47735",
    "CVE-2024-47737",
    "CVE-2024-47739",
    "CVE-2024-47740",
    "CVE-2024-47742",
    "CVE-2024-47747",
    "CVE-2024-47748",
    "CVE-2024-47749",
    "CVE-2024-47756",
    "CVE-2024-47757",
    "CVE-2024-49851",
    "CVE-2024-49852",
    "CVE-2024-49856",
    "CVE-2024-49858",
    "CVE-2024-49860",
    "CVE-2024-49866",
    "CVE-2024-49867",
    "CVE-2024-49868",
    "CVE-2024-49871",
    "CVE-2024-49875",
    "CVE-2024-49877",
    "CVE-2024-49878",
    "CVE-2024-49879",
    "CVE-2024-49881",
    "CVE-2024-49882",
    "CVE-2024-49883",
    "CVE-2024-49884",
    "CVE-2024-49886",
    "CVE-2024-49889",
    "CVE-2024-49890",
    "CVE-2024-49892",
    "CVE-2024-49894",
    "CVE-2024-49895",
    "CVE-2024-49896",
    "CVE-2024-49900",
    "CVE-2024-49902",
    "CVE-2024-49903",
    "CVE-2024-49907",
    "CVE-2024-49913",
    "CVE-2024-49924",
    "CVE-2024-49927",
    "CVE-2024-49930",
    "CVE-2024-49933",
    "CVE-2024-49935",
    "CVE-2024-49936",
    "CVE-2024-49938",
    "CVE-2024-49944",
    "CVE-2024-49946",
    "CVE-2024-49948",
    "CVE-2024-49949",
    "CVE-2024-49952",
    "CVE-2024-49954",
    "CVE-2024-49955",
    "CVE-2024-49957",
    "CVE-2024-49959",
    "CVE-2024-49962",
    "CVE-2024-49963",
    "CVE-2024-49965",
    "CVE-2024-49966",
    "CVE-2024-49967",
    "CVE-2024-49969",
    "CVE-2024-49973",
    "CVE-2024-49977",
    "CVE-2024-49981",
    "CVE-2024-49982",
    "CVE-2024-49983",
    "CVE-2024-49985",
    "CVE-2024-49993",
    "CVE-2024-49995",
    "CVE-2024-49997",
    "CVE-2024-50000",
    "CVE-2024-50001",
    "CVE-2024-50002",
    "CVE-2024-50003",
    "CVE-2024-50006",
    "CVE-2024-50007",
    "CVE-2024-50008",
    "CVE-2024-50010",
    "CVE-2024-50013",
    "CVE-2024-50015",
    "CVE-2024-50019",
    "CVE-2024-50024",
    "CVE-2024-50031",
    "CVE-2024-50033",
    "CVE-2024-50035",
    "CVE-2024-50038",
    "CVE-2024-50039",
    "CVE-2024-50040",
    "CVE-2024-50041",
    "CVE-2024-50044",
    "CVE-2024-50045",
    "CVE-2024-50046",
    "CVE-2024-50049",
    "CVE-2024-50059",
    "CVE-2024-50062",
    "CVE-2024-50072",
    "CVE-2024-50074",
    "CVE-2024-50082",
    "CVE-2024-50083",
    "CVE-2024-50086",
    "CVE-2024-50089",
    "CVE-2024-50093",
    "CVE-2024-50095",
    "CVE-2024-50096",
    "CVE-2024-50099",
    "CVE-2024-50101",
    "CVE-2024-50103",
    "CVE-2024-50110",
    "CVE-2024-50115",
    "CVE-2024-50116",
    "CVE-2024-50117",
    "CVE-2024-50127",
    "CVE-2024-50128",
    "CVE-2024-50131",
    "CVE-2024-50134",
    "CVE-2024-50141",
    "CVE-2024-50142",
    "CVE-2024-50143",
    "CVE-2024-50148",
    "CVE-2024-50150",
    "CVE-2024-50151",
    "CVE-2024-50153",
    "CVE-2024-50154",
    "CVE-2024-50156",
    "CVE-2024-50160",
    "CVE-2024-50162",
    "CVE-2024-50163",
    "CVE-2024-50167",
    "CVE-2024-50168",
    "CVE-2024-50171",
    "CVE-2024-50179",
    "CVE-2024-50180",
    "CVE-2024-50181",
    "CVE-2024-50182",
    "CVE-2024-50184",
    "CVE-2024-50185",
    "CVE-2024-50188",
    "CVE-2024-50189",
    "CVE-2024-50191",
    "CVE-2024-50192",
    "CVE-2024-50193",
    "CVE-2024-50194",
    "CVE-2024-50195",
    "CVE-2024-50196",
    "CVE-2024-50198",
    "CVE-2024-50199",
    "CVE-2024-50201",
    "CVE-2024-50202",
    "CVE-2024-50205",
    "CVE-2024-50208",
    "CVE-2024-50209",
    "CVE-2024-50210",
    "CVE-2024-50218",
    "CVE-2024-50219",
    "CVE-2024-50228",
    "CVE-2024-50229",
    "CVE-2024-50230",
    "CVE-2024-50232",
    "CVE-2024-50233",
    "CVE-2024-50234",
    "CVE-2024-50236",
    "CVE-2024-50237",
    "CVE-2024-50244",
    "CVE-2024-50245",
    "CVE-2024-50247",
    "CVE-2024-50249",
    "CVE-2024-50251",
    "CVE-2024-50257",
    "CVE-2024-50259",
    "CVE-2024-50262",
    "CVE-2024-53042",
    "CVE-2024-53055",
    "CVE-2024-53057",
    "CVE-2024-53058",
    "CVE-2024-53059"
  );

  script_name(english:"Oracle Linux 8 / 9 : Unbreakable Enterprise kernel (ELSA-2024-12887)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 8 / 9 host has packages installed that are affected by multiple vulnerabilities as referenced in
the ELSA-2024-12887 advisory.

    - mm: shmem: fix data-race in shmem_getattr() (Jeongjun Park) [Orabug: 37268580] {CVE-2024-50228}
    - wifi: iwlwifi: mvm: fix 6 GHz scan construction (Johannes Berg) [Orabug: 37304734] {CVE-2024-53055}
    - nilfs2: fix kernel bug due to missing clearing of checked flag (Ryusuke Konishi) [Orabug: 37268588]
    {CVE-2024-50230}
    - x86/bugs: Use code segment selector for VERW operand (Pawan Gupta) [Orabug: 37227383] {CVE-2024-50072}
    - ocfs2: pass u64 to ocfs2_truncate_inline maybe overflow (Edward Adam Davis) [Orabug: 37268563]
    {CVE-2024-50218}
    - mm/page_alloc: let GFP_ATOMIC order-0 allocs access highatomic reserves (Matt Fleming) [Orabug:
    37268568] {CVE-2024-50219}
    - nilfs2: fix potential deadlock with newly created symlinks (Ryusuke Konishi) [Orabug: 37268584]
    {CVE-2024-50229}
    - iio: adc: ad7124: fix division by zero in ad7124_set_channel_odr() (Zicheng Qu) [Orabug: 37268595]
    {CVE-2024-50232}
    - staging: iio: frequency: ad9832: fix division by zero in ad9832_calc_freqreg() (Zicheng Qu) [Orabug:
    37268597] {CVE-2024-50233}
    - wifi: iwlegacy: Clear stale interrupts before resuming device (Ville Syrjala) [Orabug: 37268602]
    {CVE-2024-50234}
    - wifi: ath10k: Fix memory leak in management tx (Manikanta Pubbisetty) [Orabug: 37268610]
    {CVE-2024-50236}
    - wifi: mac80211: do not pass a stopped vif to the driver in .get_txpower (Felix Fietkau) [Orabug:
    37268613] {CVE-2024-50237}
    - fs/ntfs3: Additional check in ni_clear() (Konstantin Komarov) [Orabug: 37268638] {CVE-2024-50244}
    - fs/ntfs3: Fix possible deadlock in mi_read (Konstantin Komarov) [Orabug: 37268644] {CVE-2024-50245}
    - fs/ntfs3: Check if more than chunk-size bytes are written (Andrew Ballance) [Orabug: 37268655]
    {CVE-2024-50247}
    - netfilter: nft_payload: sanitize offset and length before calling skb_checksum() (Pablo Neira Ayuso)
    [Orabug: 37268670] {CVE-2024-50251}
    - netfilter: Fix use-after-free in get_info() (Dong Chenchen) [Orabug: 37268689] {CVE-2024-50257}
    - bpf: Fix out-of-bounds write in trie_get_next_key() (Byeonguk Jeong) [Orabug: 37268702] {CVE-2024-50262}
    - netdevsim: Add trailing zero to terminate the string in nsim_nexthop_bucket_activity_write() (Zichen
    Xie) [Orabug: 37268697] {CVE-2024-50259}
    - net/sched: stop qdisc_tree_reduce_backlog on TC_H_ROOT (Pedro Tammela) [Orabug: 37304740]
    {CVE-2024-53057}
    - net: stmmac: TSO: Fix unbalanced DMA map/unmap for non-paged SKB data (Furong Xu) [Orabug: 37304745]
    {CVE-2024-53058}
    - wifi: iwlwifi: mvm: Fix response handling in iwl_mvm_send_recovery_cmd() (Daniel Gabay) [Orabug:
    37304749] {CVE-2024-53059}
    - ACPI: PRM: Find EFI_MEMORY_RUNTIME block for PRM handler and context (Koba Ko) [Orabug: 37264072]
    {CVE-2024-50141}
    - ksmbd: fix user-after-free from session log off (Namjae Jeon) [Orabug: 37227413] {CVE-2024-50086}
    - xfrm: validate new SA's prefixlen using SA family when sel.family is unset (Sabrina Dubroca) [Orabug:
    37264074] {CVE-2024-50142}
    - ASoC: qcom: Fix NULL Dereference in asoc_qcom_lpass_cpu_platform_probe() (Zichen Xie) [Orabug: 37252324]
    {CVE-2024-50103}
    - xfrm: fix one more kernel-infoleak in algo dumping (Petr Vaganov) [Orabug: 37252349] {CVE-2024-50110}
    - KVM: nSVM: Ignore nCR3[4:0] when loading PDPTEs from memory (Sean Christopherson) [Orabug: 37252372]
    {CVE-2024-50115}
    - nilfs2: fix kernel bug due to missing clearing of buffer delay flag (Ryusuke Konishi) [Orabug: 37252377]
    {CVE-2024-50116}
    - drm/amd: Guard against bad data for ATIF ACPI method (Mario Limonciello) [Orabug: 37252383]
    {CVE-2024-50117}
    - ALSA: firewire-lib: Avoid division by zero in apply_constraint_to_size() (Andrey Shumilin) [Orabug:
    37264274] {CVE-2024-50205}
    - posix-clock: posix-clock: Fix unbalanced locking in pc_clock_settime() (Jinjie Ruan) [Orabug: 37320233]
    {CVE-2024-50210}
    - net: sched: fix use-after-free in taprio_change() (Dmitry Antipov) [Orabug: 37252407] {CVE-2024-50127}
    - net: wwan: fix global oob in wwan_rtnl_policy (Lin Ma) [Orabug: 37252410] {CVE-2024-50128}
    - be2net: fix potential memory leak in be_xmit() (Wang Hai) [Orabug: 37264143] {CVE-2024-50167}
    - net/sun3_82586: fix potential memory leak in sun3_82586_send_packet() (Wang Hai) [Orabug: 37264149]
    {CVE-2024-50168}
    - tracing: Consider the NULL character when validating the event length (Leo Yan) [Orabug: 37252415]
    {CVE-2024-50131}
    - udf: fix uninit-value use in udf_get_fileshortad (Gianfranco Trad) [Orabug: 37264080] {CVE-2024-50143}
    - drm/vboxvideo: Replace fake VLA at end of vbva_mouse_pointer_shape with real VLA (Hans de Goede)
    [Orabug: 37252420] {CVE-2024-50134}
    - exec: don't WARN for racy path_noexec check (Mateusz Guzik) [Orabug: 37206344] {CVE-2024-50010}
    - arm64: probes: Fix uprobes for big-endian kernels (Mark Rutland) [Orabug: 37264236] {CVE-2024-50194}
    - Bluetooth: bnep: fix wild-memory-access in proto_unregister (Ye Bin) [Orabug: 37264096] {CVE-2024-50148}
    - usb: typec: altmode should keep reference to parent (Thadeu Lima de Souza Cascardo) [Orabug: 37264102]
    {CVE-2024-50150}
    - smb: client: fix OOBs when building SMB2_IOCTL request (Paulo Alcantara) [Orabug: 37264107]
    {CVE-2024-50151}
    - scsi: target: core: Fix null-ptr-deref in target_alloc_device() (Wang Hai) [Orabug: 37264112]
    {CVE-2024-50153}
    - tcp/dccp: Don't use timer_pending() in reqsk_queue_unlink(). (Kuniyuki Iwashima) [Orabug: 37264114]
    {CVE-2024-50154}
    - net: systemport: fix potential memory leak in bcm_sysport_xmit() (Wang Hai) [Orabug: 37264156]
    {CVE-2024-50171}
    - drm/msm: Avoid NULL dereference in msm_disp_state_print_regs() (Douglas Anderson) [Orabug: 37264122]
    {CVE-2024-50156}
    - RDMA/bnxt_re: Fix a bug while setting up Level-2 PBL pages (Bhargava Chenna Marreddy) [Orabug: 37264280]
    {CVE-2024-50208}
    - ALSA: hda/cs8409: Fix possible NULL dereference (Murad Masimov) [Orabug: 37264129] {CVE-2024-50160}
    - RDMA/bnxt_re: Add a check for memory allocation (Kalesh AP) [Orabug: 37264285] {CVE-2024-50209}
    - bpf: devmap: provide rxq after redirect (Florian Kauer) [Orabug: 37264132] {CVE-2024-50162}
    - bpf: Make sure internal and UAPI bpf_redirect flags don't overlap (Toke Hoiland-Jorgensen) [Orabug:
    37264134] {CVE-2024-50163}
    - nilfs2: propagate directory read errors from nilfs_find_entry() (Ryusuke Konishi) [Orabug: 37264266]
    {CVE-2024-50202}
    - tcp: fix mptcp DSS corruption due to large pmtu xmit (Paolo Abeni) [Orabug: 37227408] {CVE-2024-50083}
    - mptcp: handle consistently DSS corruption (Paolo Abeni) [Orabug: 37264210] {CVE-2024-50185}
    - irqchip/gic-v4: Don't allow a VMOVP on a dying VPE (Marc Zyngier) [Orabug: 37264231] {CVE-2024-50192}
    - pinctrl: ocelot: fix system hang on level based interrupts (Sergey Matsievskiy) [Orabug: 37264246]
    {CVE-2024-50196}
    - x86/entry_32: Clear CPU buffers after register restore in NMI return (Pawan Gupta) [Orabug: 37264234]
    {CVE-2024-50193}
    - iio: light: veml6030: fix IIO device retrieval from embedded device (Javier Carrasco) [Orabug: 37264254]
    {CVE-2024-50198}
    - drm/radeon: Fix encoder->possible_clones (Ville Syrjala) [Orabug: 37264263] {CVE-2024-50201}
    - blk-rq-qos: fix crash on rq_qos_wait vs. rq_qos_wake_function race (Omar Sandoval) [Orabug: 37227403]
    {CVE-2024-50082}
    - iommu/vt-d: Fix incorrect pci_for_each_dma_alias() for non-PCI devices (Lu Baolu) [Orabug: 37252321]
    {CVE-2024-50101}
    - KVM: Fix a data race on last_boosted_vcpu in kvm_vcpu_on_spin() (Breno Leitao) [Orabug: 36835836]
    {CVE-2024-40953}
    - secretmem: disable memfd_secret() if arch cannot set direct map (Patrick Roy) [Orabug: 37264195]
    {CVE-2024-50182}
    - mm/swapfile: skip HugeTLB pages for unuse_vma (Liu Shixin) [Orabug: 37264256] {CVE-2024-50199}
    - arm64: probes: Remove broken LDR (literal) uprobe support (Mark Rutland) [Orabug: 37252316]
    {CVE-2024-50099}
    - posix-clock: Fix missing timespec64 check in pc_clock_settime() (Jinjie Ruan) [Orabug: 37264241]
    {CVE-2024-50195}
    - udf: Fix bogus checksum computation in udf_rename() (Jan Kara) [Orabug: 37320204] {CVE-2024-43845}
    - ACPI: CPPC: Make rmw_lock a raw_spin_lock (Pierre Gondois) [Orabug: 37268714] {CVE-2024-50249}
    - parport: Proper fix for array out-of-bounds access (Takashi Iwai) [Orabug: 37227435] {CVE-2024-50074}
    - ipv4: ip_tunnel: Fix suspicious RCU usage warning in ip_tunnel_init_flow() (Ido Schimmel) [Orabug:
    37304697] {CVE-2024-53042}
    - scsi: lpfc: Revise lpfc_prep_embed_io routine with proper endian macro usages (Justin Tee)  [Orabug:
    37070103]  {CVE-2024-43816}
    - blk-cgroup: fix list corruption from reorder of WRITE ->lqueued (Ming Lei)  [Orabug: 37264361]
    {CVE-2024-38384}
    - blk-cgroup: fix list corruption from resetting io stat (Ming Lei)  [Orabug: 37264361] {CVE-2024-38663}
    - net: mana: Fix RX buf alloc_size alignment and atomic op panic (Haiyang Zhang)  [Orabug: 37029115]
    {CVE-2024-45001}
    - kthread: unpark only parked kthread (Frederic Weisbecker) [Orabug: 37206395] {CVE-2024-50019}
    - nouveau/dmem: Fix vulnerability in migrate_to_ram upon copy error (Yonatan Maman) [Orabug: 37252307]
    {CVE-2024-50096}
    - net: Fix an unsafe loop on the list (Anastasia Kovaleva) [Orabug: 37206408] {CVE-2024-50024}
    - drm/v3d: Stop the active perfmon before being destroyed (Maira Canal) [Orabug: 37206424]
    {CVE-2024-50031}
    - resource: fix region_intersects() vs add_memory_driver_managed() (Huang Ying) [Orabug: 37200930]
    {CVE-2024-49878}
    - HID: amd_sfh: Switch to device-managed dmam_alloc_coherent() (Basavaraj Natikar) [Orabug: 37264222]
    {CVE-2024-50189}
    - RDMA/hns: Fix UAF for cq async event (Chengchang Tang) [Orabug: 36753395] {CVE-2024-38545}
    - slip: make slhc_remember() more robust against malicious packets (Eric Dumazet) [Orabug: 37206428]
    {CVE-2024-50033}
    - ppp: fix ppp_async_encode() illegal access (Eric Dumazet) [Orabug: 37206434] {CVE-2024-50035}
    - netfilter: xtables: avoid NFPROTO_UNSPEC where needed (Florian Westphal) [Orabug: 37206449]
    {CVE-2024-50038}
    - net/sched: accept TCA_STAB only for root qdisc (Eric Dumazet) [Orabug: 37206456] {CVE-2024-50039}
    - igb: Do not bring the device up after non-fatal error (Mohamed Khalfella) [Orabug: 37206463]
    {CVE-2024-50040}
    - i40e: Fix macvlan leak by synchronizing access to mac_filter_hash (Aleksandr Loktionov) [Orabug:
    37206468] {CVE-2024-50041}
    - thermal: intel: int340x: processor: Fix warning during module unload (Zhang Rui) [Orabug: 37252297]
    {CVE-2024-50093}
    - Bluetooth: RFCOMM: FIX possible deadlock in rfcomm_sk_state_change (Luiz Augusto von Dentz) [Orabug:
    37206473] {CVE-2024-50044}
    - netfilter: br_netfilter: fix panic with metadata_dst skb (Andy Roulin) [Orabug: 37206481]
    {CVE-2024-50045}
    - net: phy: dp83869: fix memory corruption when enabling fiber (Ingo van Lil) [Orabug: 37264220]
    {CVE-2024-50188}
    - NFSv4: Prevent NULL-pointer dereference in nfs42_complete_copies() (Yanjun Zhang) [Orabug: 37206486]
    {CVE-2024-50046}
    - fbdev: sisfb: Fix strbuf array overflow (Andrey Shumilin) [Orabug: 37264185] {CVE-2024-50180}
    - drm/amd/display: Check null pointer before dereferencing se (Alex Hung) [Orabug: 37206502]
    {CVE-2024-50049}
    - virtio_pmem: Check device status before requesting flush (Philip Chen) [Orabug: 37264203]
    {CVE-2024-50184}
    - clk: imx: Remove CLK_SET_PARENT_GATE for DRAM mux for i.MX7D (Peng Fan) [Orabug: 37264190]
    {CVE-2024-50181}
    - ntb: ntb_hw_switchtec: Fix use after free vulnerability in switchtec_ntb_remove due to race condition
    (Kaixin Wang) [Orabug: 37206539] {CVE-2024-50059}
    - RDMA/rtrs-srv: Avoid null pointer deref during path establishment (Md Haris Iqbal) [Orabug: 37206562]
    {CVE-2024-50062}
    - RDMA/mad: Improve handling of timed out WRs of mad agent (Saravanan Vajravel) [Orabug: 37252300]
    {CVE-2024-50095}
    - ext4: don't set SB_RDONLY after filesystem errors (Jan Kara) [Orabug: 37264225] {CVE-2024-50191}
    - unicode: Don't special case ignorable code points (Gabriel Krisman Bertazi) [Orabug: 37252273]
    {CVE-2024-50089}
    - ALSA: usb-audio: Fix possible NULL pointer dereference in snd_usb_pcm_has_fixed_rate() (Jaroslav Kysela)
    [Orabug: 36983951] {CVE-2023-52904}
    - 9p: add missing locking around taking dentry fid list (Dominique Martinet) [Orabug: 36774627]
    {CVE-2024-39463}
    - ACPI: battery: Fix possible crash when unregistering a battery hook (Armin Wolf) [Orabug: 37206091]
    {CVE-2024-49955}
    - r8169: add tally counter fields added with RTL8125 (Heiner Kallweit) [Orabug: 37206182] {CVE-2024-49973}
    - ext4: dax: fix overflowing extents beyond inode size when partially writing (Zhihao Cheng) [Orabug:
    37206370] {CVE-2024-50015}
    - drm/amd/display: Fix system hang while resume with TBT monitor (Tom Chung) [Orabug: 37206307]
    {CVE-2024-50003}
    - tracing/timerlat: Fix a race during cpuhp processing (Wei Li) [Orabug: 37200894] {CVE-2024-49866}
    - btrfs: wait for fixup workers before stopping cleaner kthread during umount (Filipe Manana) [Orabug:
    37200896] {CVE-2024-49867}
    - btrfs: fix a NULL pointer dereference when failed to start a new trasacntion (Qu Wenruo) [Orabug:
    37200902] {CVE-2024-49868}
    - Input: adp5589-keys - fix NULL pointer dereference (Nuno Sa) [Orabug: 37200911] {CVE-2024-49871}
    - net: stmmac: Fix zero-division error when disabling tc cbs (KhaiWenTan) [Orabug: 37206640]
    {CVE-2024-49977}
    - media: venus: fix use after free bug in venus_remove due to race condition (Zheng Wang) [Orabug:
    37206208] {CVE-2024-49981}
    - aoe: fix the potential use-after-free problem in more places (Chun-Yi Lee) [Orabug: 37206641]
    {CVE-2024-49982}
    - nfsd: map the EBADMSG to nfserr_io to avoid warning (Li Lingfeng) [Orabug: 37200917] {CVE-2024-49875}
    - exfat: fix memory leak in exfat_load_bitmap() (Yuezhang Mo) [Orabug: 37206359] {CVE-2024-50013}
    - ext4: update orig_path in ext4_find_extent() (Baokun Li) [Orabug: 37200941] {CVE-2024-49881}
    - ext4: fix double brelse() the buffer of the extents path (Baokun Li) [Orabug: 37200947] {CVE-2024-49882}
    - ext4: aovid use-after-free in ext4_ext_insert_extent() (Baokun Li) [Orabug: 37200953] {CVE-2024-49883}
    - ext4: drop ppath from ext4_ext_replay_update_ex() to avoid double-free (Baokun Li) [Orabug: 37206215]
    {CVE-2024-49983}
    - ext4: fix slab-use-after-free in ext4_split_extent_at() (Baokun Li) [Orabug: 37200959] {CVE-2024-49884}
    - ext4: no need to continue when the number of entries is 1 (Edward Adam Davis) [Orabug: 37206145]
    {CVE-2024-49967}
    - i2c: stm32f7: Do not prepare/unprepare clock during runtime suspend/resume (Marek Vasut) [Orabug:
    37206219] {CVE-2024-49985}
    - platform/x86: ISST: Fix the KASAN report slab-out-of-bounds bug (Zach Wade) [Orabug: 37200965]
    {CVE-2024-49886}
    - usb: typec: tcpm: Check for port partner validity before consuming it (Badhri Jagan Sridharan) [Orabug:
    36683242] {CVE-2024-36893}
    - ext4: fix i_data_sem unlock order in ext4_ind_migrate() (Artem Sadovnikov) [Orabug: 37206322]
    {CVE-2024-50006}
    - ext4: avoid use-after-free in ext4_ext_show_leaf() (Baokun Li) [Orabug: 37205705] {CVE-2024-49889}
    - drm/amd/pm: ensure the fw_info is not null before using it (Tim Huang) [Orabug: 37205712]
    {CVE-2024-49890}
    - drm/amd/display: Initialize get_bytes_per_element's default to 1 (Alex Hung) [Orabug: 37205726]
    {CVE-2024-49892}
    - drm/amd/display: Fix index out of bounds in DCN30 color transformation (Srinivasan Shanmugam) [Orabug:
    37206158] {CVE-2024-49969} {CVE-2024-49895}
    - drm/amd/display: Fix index out of bounds in degamma hardware format translation (Srinivasan Shanmugam)
    [Orabug: 37205739] {CVE-2024-49894}
    - drm/amd/display: Fix index out of bounds in DCN30 degamma hardware format translation (Srinivasan
    Shanmugam) [Orabug: 37205745] {CVE-2024-49895} {CVE-2024-49969}
    - drm/amd/display: Check stream before comparing them (Alex Hung) [Orabug: 37205751] {CVE-2024-49896}
    - jfs: Fix uninit-value access of new_ea in ea_buffer (Zhao Mengmeng) [Orabug: 37205777] {CVE-2024-49900}
    - jfs: check if leafidx greater than num leaves per dmap tree (Edward Adam Davis) [Orabug: 37205789]
    {CVE-2024-49902}
    - jfs: Fix uaf in dbFreeBits (Edward Adam Davis) [Orabug: 37205794] {CVE-2024-49903}
    - drm/amd/display: Check null pointers before using dc->clk_mgr (Alex Hung) [Orabug: 37205820]
    {CVE-2024-49907}
    - drm/amd/display: Add null check for top_pipe_to_program in commit_planes_for_stream (Srinivasan
    Shanmugam) [Orabug: 37205857] {CVE-2024-49913}
    - iommu/vt-d: Fix potential lockup if qi_submit_sync called with 0 count (Sanjay K Kumar) [Orabug:
    37206262] {CVE-2024-49993}
    - fbdev: pxafb: Fix possible use after free in pxafb_task() (Kaixin Wang) [Orabug: 37205935]
    {CVE-2024-49924}
    - ALSA: asihpi: Fix potential OOB array access (Takashi Iwai) [Orabug: 37206327] {CVE-2024-50007}
    - x86/ioapic: Handle allocation failures gracefully (Thomas Gleixner) [Orabug: 37205954] {CVE-2024-49927}
    - wifi: mwifiex: Fix memcpy() field-spanning write warning in mwifiex_cmd_802_11_scan_ext() (Gustavo A. R.
    Silva) [Orabug: 37206332] {CVE-2024-50008}
    - tipc: guard against string buffer overrun (Simon Horman) [Orabug: 37206276] {CVE-2024-49995}
    - ACPICA: check null return of ACPI_ALLOCATE_ZEROED() in acpi_db_convert_to_package() (Pei Xiao) [Orabug:
    37206122] {CVE-2024-49962}
    - wifi: ath11k: fix array out-of-bound access in SoC stats (Karthikeyan Periyasamy) [Orabug: 37205975]
    {CVE-2024-49930}
    - blk_iocost: fix more out of bound shifts (Konstantin Ovsepian) [Orabug: 37205994] {CVE-2024-49933}
    - ACPI: PAD: fix crash in exit_round_robin() (Seiji Nishikawa) [Orabug: 37206005] {CVE-2024-49935}
    - net/xen-netback: prevent UAF in xenvif_flush_hash() (Jeongjun Park) [Orabug: 37206011] {CVE-2024-49936}
    - wifi: ath9k_htc: Use __skb_set_length() for resetting urb before resubmit (Toke Hoiland-Jorgensen)
    [Orabug: 37206028] {CVE-2024-49938}
    - f2fs: Require FMODE_WRITE for atomic write ioctls (Jann Horn) [Orabug: 37200793] {CVE-2024-47740}
    - media: usbtv: Remove useless locks in usbtv_video_free() (Benjamin Gaignard) [Orabug: 36598250]
    {CVE-2024-27072}
    - sctp: set sk_state back to CLOSED if autobind fails in sctp_listen_start (Xin Long) [Orabug: 37206050]
    {CVE-2024-49944}
    - ppp: do not assume bh is held in ppp_channel_bridge_input() (Eric Dumazet) [Orabug: 37206060]
    {CVE-2024-49946}
    - net: add more sanity checks to qdisc_pkt_len_init() (Eric Dumazet) [Orabug: 37206063] {CVE-2024-49948}
    - net: avoid potential underflow in qdisc_pkt_len_init() with UFO (Eric Dumazet) [Orabug: 37206069]
    {CVE-2024-49949}
    - net: ethernet: lantiq_etop: fix memory disclosure (Aleksander Jan Bajkowski) [Orabug: 37206288]
    {CVE-2024-49997}
    - netfilter: nf_tables: prevent nf_skb_duplicated corruption (Eric Dumazet) [Orabug: 37206080]
    {CVE-2024-49952}
    - net/mlx5e: Fix NULL deref in mlx5e_tir_builder_alloc() (Elena Salomatkina) [Orabug: 37206298]
    {CVE-2024-50000}
    - net/mlx5: Fix error path in multi-packet WQE transmit (Gerd Bayer) [Orabug: 37206301] {CVE-2024-50001}
    - ceph: remove the incorrect Fw reference check when dirtying pages (Xiubo Li) [Orabug: 37264180]
    {CVE-2024-50179}
    - mailbox: bcm2835: Fix timeout during suspend mode (Stefan Wahren) [Orabug: 37206129] {CVE-2024-49963}
    - static_call: Replace pointless WARN_ON() in static_call_module_notify() (Thomas Gleixner) [Orabug:
    37206089] {CVE-2024-49954}
    - static_call: Handle module init failure correctly in static_call_del_module() (Thomas Gleixner) [Orabug:
    37206305] {CVE-2024-50002}
    - padata: use integer wrap around to prevent deadlock on seq_nr overflow (VanGiang Nguyen) [Orabug:
    37200789] {CVE-2024-47739}
    - vfs: fix race between evice_inodes() and find_inode()&iput() (Julian Sun) [Orabug: 37200603]
    {CVE-2024-47679}
    - efistub/tpm: Use ACPI reclaim memory for event log to avoid corruption (Ard Biesheuvel) [Orabug:
    37200864] {CVE-2024-49858}
    - ACPI: sysfs: validate return type of _STR method (Thomas Weissschuh) [Orabug: 37200877] {CVE-2024-49860}
    - firmware_loader: Block path traversal (Jann Horn) [Orabug: 37200801] {CVE-2024-47742}
    - selinux,smack: don't bypass permissions check in inode_setsecctx hook (Scott Mayhew) [Orabug: 37070761]
    {CVE-2024-46695}
    - vfio/pci: fix potential memory leak in vfio_intx_enable() (Ye Bin) [Orabug: 36765615] {CVE-2024-38632}
    - bonding: Fix unnecessary warnings and logs from bond_xdp_get_xmit_slave() (Jiwon Kim) [Orabug: 37200774]
    {CVE-2024-47734}
    - tcp: check skb is non-NULL in tcp_rto_delta_us() (Josh Hunt) [Orabug: 37200622] {CVE-2024-47684}
    - net: seeq: Fix use after free vulnerability in ether3 Driver Due to Race Condition (Kaixin Wang)
    [Orabug: 37200817] {CVE-2024-47747}
    - netfilter: nf_reject_ipv6: fix nf_reject_ip6_tcphdr_put() (Eric Dumazet) [Orabug: 37200629]
    {CVE-2024-47685}
    - vhost_vdpa: assign irq bypass producer token correctly (Jason Wang) [Orabug: 37200820] {CVE-2024-47748}
    - f2fs: get rid of online repaire on corrupted directory (Chao Yu) [Orabug: 37200641] {CVE-2024-47690}
    - nfsd: return -EINVAL when namelen is 0 (Li Lingfeng) [Orabug: 37200649] {CVE-2024-47692}
    - nfsd: call cache_put if xdr_reserve_space returns NULL (Guoqing Jiang) [Orabug: 37200782]
    {CVE-2024-47737}
    - RDMA/cxgb4: Added NULL check for lookup_atid (Mikhail Lobanov) [Orabug: 37200823] {CVE-2024-47749}
    - RDMA/hns: Fix spin_unlock_irqrestore() called with IRQs enabled (Chengchang Tang) [Orabug: 37200776]
    {CVE-2024-47735}
    - IB/core: Fix ib_cache_setup_one error flow cleanup (Patrisious Haddad) [Orabug: 37200653]
    {CVE-2024-47693}
    - RDMA/rtrs-clt: Reset cid to con_num - 1 to stay in bounds (Md Haris Iqbal) [Orabug: 37200658]
    {CVE-2024-47695}
    - RDMA/iwcm: Fix WARNING:at_kernel/workqueue.c:#check_flush_dependency (Zhu Yanjun) [Orabug: 37205520]
    {CVE-2024-47696}
    - PCI: keystone: Fix if-statement expression in ks_pcie_quirk() (Dan Carpenter) [Orabug: 37205559]
    {CVE-2024-47756}
    - drivers: media: dvb-frontends/rtl2830: fix an out-of-bounds write error (Junlin Li) [Orabug: 37200661]
    {CVE-2024-47697}
    - drivers: media: dvb-frontends/rtl2832: fix an out-of-bounds write error (Junlin Li) [Orabug: 37200668]
    {CVE-2024-47698}
    - nilfs2: fix potential oob read in nilfs_btree_check_delete() (Ryusuke Konishi) [Orabug: 37200842]
    {CVE-2024-47757}
    - nilfs2: fix potential null-ptr-deref in nilfs_btree_insert() (Ryusuke Konishi) [Orabug: 37200675]
    {CVE-2024-47699}
    - ext4: avoid OOB when system.data xattr changes underneath the filesystem (Thadeu Lima de Souza Cascardo)
    [Orabug: 37200681] {CVE-2024-47701}
    - tpm: Clean up TPM space after command failure (Jonathan McDowell) [Orabug: 37200850] {CVE-2024-49851}
    - jfs: fix out-of-bounds in dbNextAG() and diAlloc() (Jeongjun Park) [Orabug: 37200739] {CVE-2024-47723}
    - scsi: elx: libefc: Fix potential use after free in efc_nport_vport_del() (Dan Carpenter) [Orabug:
    37200855] {CVE-2024-49852}
    - drm/amd/display: Add null check for set_output_gamma in dcn30_set_output_transfer_func (Srinivasan
    Shanmugam) [Orabug: 37200736] {CVE-2024-47720}
    - block: fix potential invalid pointer dereference in blk_add_partition (Riyan Dhiman) [Orabug: 37200698]
    {CVE-2024-47705}
    - can: bcm: Clear bo->bcm_proc_read after remove_proc_entry(). (Kuniyuki Iwashima) [Orabug: 37205475]
    {CVE-2024-47709}
    - sock_map: Add a cond_resched() in sock_hash_free() (Eric Dumazet) [Orabug: 37200714] {CVE-2024-47710}
    - wifi: wilc1000: fix potential RCU dereference issue in wilc_parse_join_bss_param (Jiawei Ye) [Orabug:
    37205501] {CVE-2024-47712}
    - wifi: mac80211: use two-phase skb reclamation in ieee80211_do_stop() (Dmitry Antipov) [Orabug: 37200719]
    {CVE-2024-47713}
    - x86/sgx: Fix deadlock in SGX NUMA node search (Aaron Lu) [Orabug: 37200860] {CVE-2024-49856}
    - wifi: rtw88: always wait for both firmware loading attempts (Dmitry Antipov) [Orabug: 37200733]
    {CVE-2024-47718}
    - USB: usbtmc: prevent kernel-usb-infoleak (Edward Adam Davis) [Orabug: 37159777] {CVE-2024-47671}
    - inet: inet_defrag: prevent sk release while still in use (Florian Westphal) [Orabug: 36545059]
    {CVE-2024-26921}
    - gpio: prevent potential speculation leaks in gpio_device_get_desc() (Hagar Hemdan) [Orabug: 36993133]
    {CVE-2024-44931}
    - netfilter: nft_set_pipapo: walk over current view on netlink dump (Pablo Neira Ayuso) [Orabug: 36598033]
    {CVE-2024-27017}
    - ocfs2: strict bound check before memcmp in ocfs2_xattr_find_entry() (Ferry Meng) [Orabug: 36891660]
    {CVE-2024-41016}
    - ocfs2: add bounds checking to ocfs2_xattr_find_entry() (Ferry Meng) [Orabug: 37159772] {CVE-2024-47670}
    - wifi: iwlwifi: mvm: don't wait for tx queues if firmware is dead (Emmanuel Grumbach) [Orabug: 37159780]
    {CVE-2024-47672}
    - wifi: iwlwifi: mvm: pause TCM when the firmware is stopped (Emmanuel Grumbach) [Orabug: 37159785]
    {CVE-2024-47673}
    - ASoC: meson: axg-card: fix 'use-after-free' (Arseniy Krasnov) [Orabug: 37116539] {CVE-2024-46849}
    - dma-buf: heaps: Fix off-by-one in CMA heap fault handler (T.J. Mercier) [Orabug: 37116545]
    {CVE-2024-46852}
    - spi: nxp-fspi: fix the KASAN report out-of-bounds bug (Han Xu) [Orabug: 37116547] {CVE-2024-46853}
    - net: dpaa: Pad packets to ETH_ZLEN (Sean Anderson) [Orabug: 37116550] {CVE-2024-46854}
    - netfilter: nft_socket: fix sk refcount leaks (Florian Westphal) [Orabug: 37116554] {CVE-2024-46855}
    - fou: fix initialization of grc (Muhammad Usama Anjum) [Orabug: 37195062] {CVE-2024-46865}
    - mptcp: pm: Fix uaf in __timer_delete_sync (Edward Adam Davis) [Orabug: 37116564] {CVE-2024-46858}
    - platform/x86: panasonic-laptop: Fix SINF array out of bounds accesses (Hans de Goede) [Orabug: 37116566]
    {CVE-2024-46859}
    - ocfs2: fix possible null-ptr-deref in ocfs2_set_buffer_uptodate (Lizhi Xu) [Orabug: 37200925]
    {CVE-2024-49877}
    - ocfs2: fix null-ptr-deref when journal load failed. (Julian Sun) [Orabug: 37206096] {CVE-2024-49957}
    - ocfs2: remove unreasonable unlock in ocfs2_read_blocks (Lizhi Xu) [Orabug: 37206135] {CVE-2024-49965}
    - ocfs2: cancel dqi_sync_work before freeing oinfo (Joseph Qi) [Orabug: 37206140] {CVE-2024-49966}
    - jbd2: stop waiting for space when jbd2_cleanup_journal_tail() returns error (Baokun Li) [Orabug:
    37206108] {CVE-2024-49959}
    - drm: omapdrm: Add missing check for alloc_ordered_workqueue (Ma Ke) [Orabug: 37200934] {CVE-2024-49879}
    in of_msi_get_domain (Andrew Jones)

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2024-12887.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-47685");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/12/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:8::UEKR7");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:9::UEKR7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:9:5:baseos_patch");
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
  var fixed_uptrack_levels = ['5.15.0-303.171.5.2.el8uek', '5.15.0-303.171.5.2.el9uek'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2024-12887');
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
    {'reference':'bpftool-5.15.0-303.171.5.2.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'bpftool-5.15.0'},
    {'reference':'kernel-uek-5.15.0-303.171.5.2.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-5.15.0'},
    {'reference':'kernel-uek-container-5.15.0-303.171.5.2.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-container-5.15.0'},
    {'reference':'kernel-uek-container-debug-5.15.0-303.171.5.2.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-container-debug-5.15.0'},
    {'reference':'kernel-uek-core-5.15.0-303.171.5.2.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-core-5.15.0'},
    {'reference':'kernel-uek-debug-5.15.0-303.171.5.2.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-5.15.0'},
    {'reference':'kernel-uek-debug-core-5.15.0-303.171.5.2.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-core-5.15.0'},
    {'reference':'kernel-uek-debug-devel-5.15.0-303.171.5.2.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-5.15.0'},
    {'reference':'kernel-uek-debug-modules-5.15.0-303.171.5.2.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-modules-5.15.0'},
    {'reference':'kernel-uek-debug-modules-extra-5.15.0-303.171.5.2.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-modules-extra-5.15.0'},
    {'reference':'kernel-uek-devel-5.15.0-303.171.5.2.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-5.15.0'},
    {'reference':'kernel-uek-doc-5.15.0-303.171.5.2.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-5.15.0'},
    {'reference':'kernel-uek-modules-5.15.0-303.171.5.2.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-modules-5.15.0'},
    {'reference':'kernel-uek-modules-extra-5.15.0-303.171.5.2.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-modules-extra-5.15.0'},
    {'reference':'bpftool-5.15.0-303.171.5.2.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'bpftool-5.15.0'},
    {'reference':'kernel-uek-5.15.0-303.171.5.2.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-5.15.0'},
    {'reference':'kernel-uek-container-5.15.0-303.171.5.2.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-container-5.15.0'},
    {'reference':'kernel-uek-container-debug-5.15.0-303.171.5.2.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-container-debug-5.15.0'},
    {'reference':'kernel-uek-core-5.15.0-303.171.5.2.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-core-5.15.0'},
    {'reference':'kernel-uek-debug-5.15.0-303.171.5.2.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-5.15.0'},
    {'reference':'kernel-uek-debug-core-5.15.0-303.171.5.2.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-core-5.15.0'},
    {'reference':'kernel-uek-debug-devel-5.15.0-303.171.5.2.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-5.15.0'},
    {'reference':'kernel-uek-debug-modules-5.15.0-303.171.5.2.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-modules-5.15.0'},
    {'reference':'kernel-uek-debug-modules-extra-5.15.0-303.171.5.2.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-modules-extra-5.15.0'},
    {'reference':'kernel-uek-devel-5.15.0-303.171.5.2.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-5.15.0'},
    {'reference':'kernel-uek-doc-5.15.0-303.171.5.2.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-5.15.0'},
    {'reference':'kernel-uek-modules-5.15.0-303.171.5.2.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-modules-5.15.0'},
    {'reference':'kernel-uek-modules-extra-5.15.0-303.171.5.2.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-modules-extra-5.15.0'},
    {'reference':'bpftool-5.15.0-303.171.5.2.el9uek', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'bpftool-5.15.0'},
    {'reference':'kernel-uek-5.15.0-303.171.5.2.el9uek', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-5.15.0'},
    {'reference':'kernel-uek-container-5.15.0-303.171.5.2.el9uek', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-container-5.15.0'},
    {'reference':'kernel-uek-container-debug-5.15.0-303.171.5.2.el9uek', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-container-debug-5.15.0'},
    {'reference':'kernel-uek-core-5.15.0-303.171.5.2.el9uek', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-core-5.15.0'},
    {'reference':'kernel-uek-debug-5.15.0-303.171.5.2.el9uek', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-5.15.0'},
    {'reference':'kernel-uek-debug-core-5.15.0-303.171.5.2.el9uek', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-core-5.15.0'},
    {'reference':'kernel-uek-debug-devel-5.15.0-303.171.5.2.el9uek', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-5.15.0'},
    {'reference':'kernel-uek-debug-modules-5.15.0-303.171.5.2.el9uek', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-modules-5.15.0'},
    {'reference':'kernel-uek-debug-modules-extra-5.15.0-303.171.5.2.el9uek', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-modules-extra-5.15.0'},
    {'reference':'kernel-uek-devel-5.15.0-303.171.5.2.el9uek', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-5.15.0'},
    {'reference':'kernel-uek-doc-5.15.0-303.171.5.2.el9uek', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-5.15.0'},
    {'reference':'kernel-uek-modules-5.15.0-303.171.5.2.el9uek', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-modules-5.15.0'},
    {'reference':'kernel-uek-modules-extra-5.15.0-303.171.5.2.el9uek', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-modules-extra-5.15.0'},
    {'reference':'bpftool-5.15.0-303.171.5.2.el9uek', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'bpftool-5.15.0'},
    {'reference':'kernel-uek-5.15.0-303.171.5.2.el9uek', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-5.15.0'},
    {'reference':'kernel-uek-container-5.15.0-303.171.5.2.el9uek', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-container-5.15.0'},
    {'reference':'kernel-uek-container-debug-5.15.0-303.171.5.2.el9uek', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-container-debug-5.15.0'},
    {'reference':'kernel-uek-core-5.15.0-303.171.5.2.el9uek', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-core-5.15.0'},
    {'reference':'kernel-uek-debug-5.15.0-303.171.5.2.el9uek', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-5.15.0'},
    {'reference':'kernel-uek-debug-core-5.15.0-303.171.5.2.el9uek', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-core-5.15.0'},
    {'reference':'kernel-uek-debug-devel-5.15.0-303.171.5.2.el9uek', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-5.15.0'},
    {'reference':'kernel-uek-debug-modules-5.15.0-303.171.5.2.el9uek', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-modules-5.15.0'},
    {'reference':'kernel-uek-debug-modules-extra-5.15.0-303.171.5.2.el9uek', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-modules-extra-5.15.0'},
    {'reference':'kernel-uek-devel-5.15.0-303.171.5.2.el9uek', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-5.15.0'},
    {'reference':'kernel-uek-doc-5.15.0-303.171.5.2.el9uek', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-5.15.0'},
    {'reference':'kernel-uek-modules-5.15.0-303.171.5.2.el9uek', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-modules-5.15.0'},
    {'reference':'kernel-uek-modules-extra-5.15.0-303.171.5.2.el9uek', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-modules-extra-5.15.0'}
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
      severity   : SECURITY_HOLE,
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
