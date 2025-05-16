#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2024-12618.
##

include('compat.inc');

if (description)
{
  script_id(207042);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/21");

  script_cve_id(
    "CVE-2022-3566",
    "CVE-2022-3567",
    "CVE-2024-36032",
    "CVE-2024-36033",
    "CVE-2024-36484",
    "CVE-2024-36894",
    "CVE-2024-36901",
    "CVE-2024-36974",
    "CVE-2024-36978",
    "CVE-2024-37078",
    "CVE-2024-38588",
    "CVE-2024-38619",
    "CVE-2024-39362",
    "CVE-2024-39468",
    "CVE-2024-39469",
    "CVE-2024-39482",
    "CVE-2024-39484",
    "CVE-2024-39487",
    "CVE-2024-39495",
    "CVE-2024-39499",
    "CVE-2024-39500",
    "CVE-2024-39501",
    "CVE-2024-39502",
    "CVE-2024-39505",
    "CVE-2024-39506",
    "CVE-2024-39507",
    "CVE-2024-39509",
    "CVE-2024-40901",
    "CVE-2024-40902",
    "CVE-2024-40904",
    "CVE-2024-40905",
    "CVE-2024-40908",
    "CVE-2024-40911",
    "CVE-2024-40912",
    "CVE-2024-40914",
    "CVE-2024-40927",
    "CVE-2024-40929",
    "CVE-2024-40931",
    "CVE-2024-40932",
    "CVE-2024-40934",
    "CVE-2024-40937",
    "CVE-2024-40941",
    "CVE-2024-40942",
    "CVE-2024-40943",
    "CVE-2024-40945",
    "CVE-2024-40947",
    "CVE-2024-40956",
    "CVE-2024-40957",
    "CVE-2024-40958",
    "CVE-2024-40959",
    "CVE-2024-40960",
    "CVE-2024-40961",
    "CVE-2024-40963",
    "CVE-2024-40967",
    "CVE-2024-40968",
    "CVE-2024-40970",
    "CVE-2024-40971",
    "CVE-2024-40974",
    "CVE-2024-40976",
    "CVE-2024-40978",
    "CVE-2024-40980",
    "CVE-2024-40981",
    "CVE-2024-40983",
    "CVE-2024-40987",
    "CVE-2024-40988",
    "CVE-2024-40990",
    "CVE-2024-40993",
    "CVE-2024-40994",
    "CVE-2024-40995",
    "CVE-2024-41000",
    "CVE-2024-41002",
    "CVE-2024-41005",
    "CVE-2024-41006",
    "CVE-2024-41007",
    "CVE-2024-41027",
    "CVE-2024-41034",
    "CVE-2024-41035",
    "CVE-2024-41040",
    "CVE-2024-41041",
    "CVE-2024-41044",
    "CVE-2024-41046",
    "CVE-2024-41047",
    "CVE-2024-41048",
    "CVE-2024-41049",
    "CVE-2024-41087",
    "CVE-2024-41089",
    "CVE-2024-41092",
    "CVE-2024-41093",
    "CVE-2024-41095",
    "CVE-2024-41097",
    "CVE-2024-42068",
    "CVE-2024-42069",
    "CVE-2024-42070",
    "CVE-2024-42076",
    "CVE-2024-42077",
    "CVE-2024-42080",
    "CVE-2024-42082",
    "CVE-2024-42084",
    "CVE-2024-42085",
    "CVE-2024-42086",
    "CVE-2024-42087",
    "CVE-2024-42089",
    "CVE-2024-42090",
    "CVE-2024-42092",
    "CVE-2024-42093",
    "CVE-2024-42094",
    "CVE-2024-42095",
    "CVE-2024-42096",
    "CVE-2024-42097",
    "CVE-2024-42098",
    "CVE-2024-42101",
    "CVE-2024-42103",
    "CVE-2024-42104",
    "CVE-2024-42105",
    "CVE-2024-42106",
    "CVE-2024-42109",
    "CVE-2024-42115",
    "CVE-2024-42116",
    "CVE-2024-42119",
    "CVE-2024-42120",
    "CVE-2024-42121",
    "CVE-2024-42124",
    "CVE-2024-42127",
    "CVE-2024-42130",
    "CVE-2024-42131",
    "CVE-2024-42137",
    "CVE-2024-42140",
    "CVE-2024-42143",
    "CVE-2024-42145",
    "CVE-2024-42148",
    "CVE-2024-42152",
    "CVE-2024-42153",
    "CVE-2024-42154",
    "CVE-2024-42157",
    "CVE-2024-42161",
    "CVE-2024-42223",
    "CVE-2024-42224",
    "CVE-2024-42225",
    "CVE-2024-42229",
    "CVE-2024-42232",
    "CVE-2024-42236",
    "CVE-2024-42244",
    "CVE-2024-42247"
  );
  script_xref(name:"IAVA", value:"2024-A-0487");

  script_name(english:"Oracle Linux 8 / 9 : Unbreakable Enterprise kernel (ELSA-2024-12618)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 8 / 9 host has packages installed that are affected by multiple vulnerabilities as referenced in
the ELSA-2024-12618 advisory.

    - net: mana: Fix possible double free in error handling path (Ma Ke)  [Orabug: 36897038] {CVE-2024-42069}
    - net: relax socket state check at accept time. (Paolo Abeni) [Orabug: 36768888] {CVE-2024-36484}
    - nilfs2: fix kernel bug on rename operation of broken directory (Ryusuke Konishi) [Orabug: 36896820]
    {CVE-2024-41034}
    - ipv6: prevent NULL dereference in ip6_output() (Eric Dumazet) [Orabug: 36683273] {CVE-2024-36901}
    - wireguard: allowedips: avoid unaligned 64-bit memory accesses (Helge Deller) [Orabug: 36930166]
    {CVE-2024-42247}
    - libceph: fix race between delayed_work() and ceph_monc_stop() (Ilya Dryomov) [Orabug: 36930127]
    {CVE-2024-42232}
    - Fix userfaultfd_api to return EINVAL as expected (Audra Mitchell) [Orabug: 36896804] {CVE-2024-41027}
    - USB: core: Fix duplicate endpoint bug by clearing reserved bits in the descriptor (Alan Stern) [Orabug:
    36896825] {CVE-2024-41035}
    - usb: gadget: configfs: Prevent OOB read/write in usb_string_copy() (Lee Jones) [Orabug: 36930137]
    {CVE-2024-42236}
    - USB: serial: mos7840: fix crash on resume (Dmitry Smirnov) [Orabug: 36930153] {CVE-2024-42244}
    - tcp: avoid too many retransmit packets (Eric Dumazet) [Orabug: 36841815] {CVE-2024-41007}
    - net/sched: Fix UAF when resolving a clash (Chengen Du) [Orabug: 36896837] {CVE-2024-41040}
    - udp: Set SOCK_RCU_FREE earlier in udp_lib_get_port(). (Kuniyuki Iwashima) [Orabug: 36896841]
    {CVE-2024-41041}
    - ppp: reject claimed-as-LCP but actually malformed packets (Dmitry Antipov) [Orabug: 36896855]
    {CVE-2024-41044}
    - net: ethernet: lantiq_etop: fix double free in detach (Aleksander Jan Bajkowski) [Orabug: 36896862]
    {CVE-2024-41046}
    - i40e: Fix XDP program unloading while removing the driver (Michal Kubiak) [Orabug: 36896869]
    {CVE-2024-41047}
    - skmsg: Skip zero length skb in sk_msg_recvmsg (Geliang Tang) [Orabug: 36896872] {CVE-2024-41048}
    - filelock: fix potential use-after-free in posix_lock_inode (Jeff Layton) [Orabug: 36896875]
    {CVE-2024-41049}
    - nfc/nci: Add the inconsistency check between the input data length and count (Edward Adam Davis)
    [Orabug: 36897796] {CVE-2024-42130}
    - nvmet: fix a possible leak when destroy a ctrl during qp establishment (Sagi Grimberg) [Orabug:
    36897901] {CVE-2024-42152}
    - i2c: pnx: Fix potential deadlock warning from del_timer_sync() call in isr (Piotr Wojtaszczyk) [Orabug:
    36897908] {CVE-2024-42153}
    - ima: Avoid blocking in RCU read-side critical section (GUO Zihua) [Orabug: 36835827] {CVE-2024-40947}
    - bnx2x: Fix multiple UBSAN array-index-out-of-bounds (Ghadi Elie Rahme) [Orabug: 36897884]
    {CVE-2024-42148}
    - drm/nouveau: fix null pointer dereference in nouveau_connector_get_modes (Ma Ke) [Orabug: 36897639]
    {CVE-2024-42101}
    - Bluetooth: qca: Fix BT enable failure again for QCA6390 after warm reboot (Zijun Hu) [Orabug: 36897825]
    {CVE-2024-42137}
    - btrfs: fix adding block group to a reclaim list and the unused list during reclaim (Naohiro Aota)
    [Orabug: 36934739] {CVE-2024-42103}
    - mm: avoid overflows in dirty throttling logic (Jan Kara) [Orabug: 36897802] {CVE-2024-42131}
    - nilfs2: add missing check for inode numbers on directory entries (Ryusuke Konishi) [Orabug: 36897651]
    {CVE-2024-42104}
    - nilfs2: fix inode number range checks (Ryusuke Konishi) [Orabug: 36897657] {CVE-2024-42105}
    - inet_diag: Initialize pad field in struct inet_diag_req_v2 (Shigeru Yoshida) [Orabug: 36897665]
    {CVE-2024-42106}
    - bonding: Fix out-of-bounds read in bond_option_arp_ip_targets_set() (Sam Sun) [Orabug: 36825247]
    {CVE-2024-39487}
    - netfilter: nf_tables: unconditionally flush pending work before notifier (Florian Westphal) [Orabug:
    36897676] {CVE-2024-42109}
    - riscv: kexec: Avoid deadlock in kexec crash path (Song Shuai) [Orabug: 36897831] {CVE-2024-42140}
    - tcp_metrics: validate source addr length (Jakub Kicinski) [Orabug: 36897914] {CVE-2024-42154}
    - s390/pkey: Wipe sensitive data on failure (Holger Dengler) [Orabug: 36897933] {CVE-2024-42157}
    - jffs2: Fix potential illegal address access in jffs2_free_inode (Wang Yong) [Orabug: 36897693]
    {CVE-2024-42115}
    - bpf: Avoid uninitialized value in BPF_CORE_READ_BITFIELD (Jose E. Marchesi) [Orabug: 36897964]
    {CVE-2024-42161}
    - igc: fix a log entry using uninitialized netdev (Corinna Vinschen) [Orabug: 36897705] {CVE-2024-42116}
    - orangefs: fix out-of-bounds fsid access (Mike Marshall) [Orabug: 36897836] {CVE-2024-42143}
    - media: dvb-frontends: tda10048: Fix integer overflow (Ricardo Ribalda) [Orabug: 36897975]
    {CVE-2024-42223}
    - net: dsa: mv88e6xxx: Correct check for empty list (Simon Horman) [Orabug: 36897981] {CVE-2024-42224}
    - wifi: mt76: replace skb_put with skb_put_zero (Felix Fietkau) [Orabug: 36897988] {CVE-2024-42225}
    - drm/amd/display: Skip finding free audio for unknown engine_id (Alex Hung) [Orabug: 36897725]
    {CVE-2024-42119}
    - drm/amd/display: Check pipe offset before setting vblank (Alex Hung) [Orabug: 36897731] {CVE-2024-42120}
    - drm/amd/display: Check index msg_id before read or write (Alex Hung) [Orabug: 36897738] {CVE-2024-42121}
    - crypto: aead,cipher - zeroize key buffer after use (Hailey Mothershead) [Orabug: 36898013]
    {CVE-2024-42229}
    - scsi: qedf: Make qedf_execute_tmf() non-preemptible (John Meneghini) [Orabug: 36897759] {CVE-2024-42124}
    - IB/core: Implement a limit on UMAD receive List (Michael Guralnik) [Orabug: 36897846] {CVE-2024-42145}
    - drm/lima: fix shared irq handling on driver remove (Erico Nunes) [Orabug: 36897778] {CVE-2024-42127}
    - tcp: Fix data races around icsk->icsk_af_ops. (Kuniyuki Iwashima) [Orabug: 34719865] {CVE-2022-3566}
    - ipv6: Fix data races around sk->sk_prot. (Kuniyuki Iwashima) [Orabug: 34719905] {CVE-2022-3567}
    - ftruncate: pass a signed offset (Arnd Bergmann) [Orabug: 36897557] {CVE-2024-42084}
    - ata: libata-core: Fix double free on error (Niklas Cassel) [Orabug: 36897373] {CVE-2024-41087}
    - drm/nouveau/dispnv04: fix null pointer dereference in nv17_tv_get_hd_modes (Ma Ke) [Orabug: 36897379]
    {CVE-2024-41089}
    - drm/i915/gt: Fix potential UAF by revoke of fence registers (Janusz Krzysztofik) [Orabug: 36897385]
    {CVE-2024-41092}
    - drm/amdgpu: avoid using null object of framebuffer (Julia Zhang) [Orabug: 36897435] {CVE-2024-41093}
    - drm/nouveau/dispnv04: fix null pointer dereference in nv17_tv_get_ld_modes (Ma Ke) [Orabug: 36897442]
    {CVE-2024-41095}
    - net: can: j1939: Initialize unused data in j1939_send_one() (Shigeru Yoshida) [Orabug: 36897515]
    {CVE-2024-42076}
    - serial: 8250_omap: Implementation of Errata i2310 (Udit Kumar) [Orabug: 36897613] {CVE-2024-42095}
    - usb: dwc3: core: remove lock of otg mode during gadget suspend/resume to avoid deadlock (Meng Li)
    [Orabug: 36897563] {CVE-2024-42085}
    - usb: atm: cxacru: fix endpoint checking in cxacru_bind() (Nikita Zhandarovich) [Orabug: 36897450]
    {CVE-2024-41097}
    - iio: chemical: bme680: Fix overflows in compensate() functions (Vasileios Amoiridis) [Orabug: 36897565]
    {CVE-2024-42086}
    - ocfs2: fix DIO failure due to insufficient transaction credits (Jan Kara) [Orabug: 36897528]
    {CVE-2024-42077}
    - x86: stop playing stack games in profile_pc() (Linus Torvalds) [Orabug: 36897615] {CVE-2024-42096}
    - gpio: davinci: Validate the obtained number of IRQs (Aleksandr Mishin) [Orabug: 36897598]
    {CVE-2024-42092}
    - ALSA: emux: improve patch ioctl data validation (Oswald Buddenhagen) [Orabug: 36897623] {CVE-2024-42097}
    - crypto: ecdh - explicitly zeroize private_key (Joachim Vandersmissen) [Orabug: 36897630]
    {CVE-2024-42098}
    - net/dpaa2: Avoid explicit cpumask var allocation on stack (Dawei Li) [Orabug: 36897601] {CVE-2024-42093}
    - net/iucv: Avoid explicit cpumask var allocation on stack (Dawei Li) [Orabug: 36897607] {CVE-2024-42094}
    - RDMA/restrack: Fix potential invalid address access (Wenchao Hao) [Orabug: 36897540] {CVE-2024-42080}
    - drm/panel: ilitek-ili9881c: Fix warning with GPIO controllers that sleep (Laurent Pinchart) [Orabug:
    36897569] {CVE-2024-42087}
    - bpf: Take return from set_memory_ro() into account with bpf_prog_lock_ro() (Christophe Leroy) [Orabug:
    36897491] {CVE-2024-42068}
    - netfilter: nf_tables: fully validate NFT_DATA_VALUE on store to data registers (Pablo Neira Ayuso)
    [Orabug: 36897499] {CVE-2024-42070}
    - xdp: Remove WARN() from __xdp_reg_mem_model() (Daniil Dulov) [Orabug: 36897553] {CVE-2024-42082}
    - ASoC: fsl-asoc-card: set priv->pdev before using it (Elinor Montmasson) [Orabug: 36897577]
    {CVE-2024-42089}
    - drm/amdgpu: fix UBSAN warning in kv_dpm.c (Alex Deucher) [Orabug: 36835991] {CVE-2024-40987}
    - pinctrl: fix deadlock in create_pinctrl() when handling -EPROBE_DEFER (Hagar Hemdan) [Orabug: 36897585]
    {CVE-2024-42090}
    - gve: Clear napi->skb before dev_kfree_skb_any() (Ziwei Xiao) [Orabug: 36835798] {CVE-2024-40937}
    - smb: client: fix deadlock in smb2_find_smb_tcon() (Enzo Matsumiya) [Orabug: 36774640] {CVE-2024-39468}
    - bcache: fix variable length array abuse in btree_iter (Matthew Mirvish) [Orabug: 36809293]
    {CVE-2024-39482}
    - drm/radeon: fix UBSAN warning in kv_dpm.c (Alex Deucher) [Orabug: 36835996] {CVE-2024-40988}
    - RDMA/mlx5: Add check for srq max_sge attribute (Patrisious Haddad) [Orabug: 36836003] {CVE-2024-40990}
    - dmaengine: idxd: Fix possible Use-After-Free in irq_process_work_list (Li RongQing) [Orabug: 36835844]
    {CVE-2024-40956}
    - seg6: fix parameter passing when calling NF_HOOK() in End.DX4 and End.DX6 behaviors (Jianguo Wu)
    [Orabug: 36835846] {CVE-2024-40957}
    - netfilter: ipset: Fix suspicious rcu_dereference_protected() (Jozsef Kadlecsik) [Orabug: 36836326]
    {CVE-2024-40993}
    - ptp: fix integer overflow in max_vclocks_store (Dan Carpenter) [Orabug: 36836016] {CVE-2024-40994}
    - tipc: force a dst refcount before doing decryption (Xin Long) [Orabug: 36835980] {CVE-2024-40983}
    - net/sched: act_api: fix possible infinite loop in tcf_idr_check_alloc() (David Ruth) [Orabug: 36836018]
    {CVE-2024-40995}
    - netns: Make get_net_ns() handle zero refcount net (Yue Haibing) [Orabug: 36835848] {CVE-2024-40958}
    - xfrm6: check ip6_dst_idev() return value in xfrm6_get_saddr() (Eric Dumazet) [Orabug: 36835851]
    {CVE-2024-40959}
    - ipv6: prevent possible NULL dereference in rt6_probe() (Eric Dumazet) [Orabug: 36835856]
    {CVE-2024-40960}
    - ipv6: prevent possible NULL deref in fib6_nh_init() (Eric Dumazet) [Orabug: 36835861] {CVE-2024-40961}
    - netrom: Fix a memory leak in nr_heartbeat_expiry() (Gavrilov Ilia) [Orabug: 36836085] {CVE-2024-41006}
    - mips: bmips: BCM6358: make sure CBR is correctly set (Christian Marangi) [Orabug: 36835869]
    {CVE-2024-40963}
    - serial: imx: Introduce timeout when waiting on transmitter empty (Esben Haabendal) [Orabug: 36835886]
    {CVE-2024-40967}
    - MIPS: Octeon: Add PCIe link status check (Songyang Li) [Orabug: 36835892] {CVE-2024-40968}
    - Avoid hw_desc array overrun in dw-axi-dmac (Joao Pinto) [Orabug: 36835903] {CVE-2024-40970}
    - f2fs: remove clear SB_INLINECRYPT flag in default_options (Yunlei He) [Orabug: 36835908]
    {CVE-2024-40971}
    - powerpc/pseries: Enforce hcall result buffer validity and size (Nathan Lynch) [Orabug: 36835925]
    {CVE-2024-40974}
    - drm/lima: mask irqs in timeout path before hard reset (Erico Nunes) [Orabug: 36835935] {CVE-2024-40976}
    - netpoll: Fix race condition in netpoll_owner_active (Breno Leitao) [Orabug: 36836079] {CVE-2024-41005}
    - scsi: qedi: Fix crash while reading debugfs attribute (Manish Rangankar) [Orabug: 36835946]
    {CVE-2024-40978}
    - drop_monitor: replace spin_lock by raw_spin_lock (Wander Lairson Costa) [Orabug: 36835959]
    {CVE-2024-40980}
    - batman-adv: bypass empty buckets in batadv_purge_orig_ref() (Eric Dumazet) [Orabug: 36835965]
    {CVE-2024-40981}
    - block/ioctl: prefer different overflow check (Justin Stitt) [Orabug: 36836043] {CVE-2024-41000}
    - crypto: hisilicon/sec - Fix memory leak for sec resource release (Chenghai Huang) [Orabug: 36836053]
    {CVE-2024-41002}
    - Bluetooth: qca: fix info leak when fetching board id (Johan Hovold) [Orabug: 36934735] {CVE-2024-36033}
    - usb-storage: alauda: Check whether the media is initialized (Shichao Lai) [Orabug: 36753733]
    {CVE-2024-38619}
    - greybus: Fix use-after-free bug in gb_interface_release due to race condition. (Sicong Huang) [Orabug:
    36835563] {CVE-2024-39495}
    - mm/huge_memory: don't unpoison huge_zero_folio (Miaohe Lin) [Orabug: 36835742] {CVE-2024-40914}
    - nilfs2: fix potential kernel bug due to lack of writeback flag waiting (Ryusuke Konishi) [Orabug:
    36774570] {CVE-2024-37078}
    - ocfs2: fix races between hole punching and AIO+DIO (Su Yue) [Orabug: 36835816] {CVE-2024-40943}
    - vmci: prevent speculation leaks by sanitizing event in event_deliver() (Hagar Gamal Halim Hemdan)
    [Orabug: 36835581] {CVE-2024-39499}
    - sock_map: avoid race between sock_map_close and sk_psock_put (Thadeu Lima de Souza Cascardo) [Orabug:
    36835586] {CVE-2024-39500}
    - mptcp: ensure snd_una is properly initialized on connect (Paolo Abeni) [Orabug: 36835783]
    {CVE-2024-40931}
    - drm/exynos/vidi: fix memory leak in .get_modes() (Jani Nikula) [Orabug: 36835785] {CVE-2024-40932}
    - drivers: core: synchronize really_probe() and dev_uevent() (Dirk Behme) [Orabug: 36835588]
    {CVE-2024-39501}
    - ionic: fix use after netif_napi_del() (Taehee Yoo) [Orabug: 36835594] {CVE-2024-39502}
    - drm/komeda: check for error-valued pointer (Amjad Ouled-Ameur) [Orabug: 36835673] {CVE-2024-39505}
    - liquidio: Adjust a NULL pointer handling path in lio_vf_rep_copy_packet (Aleksandr Mishin) [Orabug:
    36835676] {CVE-2024-39506}
    - net: hns3: fix kernel crash problem in concurrent scenario (Yonglong Liu) [Orabug: 36835679]
    {CVE-2024-39507}
    - HID: logitech-dj: Fix memory leak in logi_dj_recv_switch_to_dj_mode() (Jose Exposito) [Orabug: 36835792]
    {CVE-2024-40934}
    - iommu: Return right value in iommu_sva_bind_device() (Lu Baolu) [Orabug: 36835823] {CVE-2024-40945}
    - HID: core: remove unnecessary WARN_ON() in implement() (Nikita Zhandarovich) [Orabug: 36835688]
    {CVE-2024-39509}
    - scsi: mpt3sas: Avoid test/set_bit() operating in non-allocated memory (Breno Leitao) [Orabug: 36835695]
    {CVE-2024-40901}
    - xhci: Handle TD clearing for multiple streams case (Hector Martin) [Orabug: 36835772] {CVE-2024-40927}
    - jfs: xattr: fix buffer overflow for invalid xattr (Greg Kroah-Hartman) [Orabug: 36835700]
    {CVE-2024-40902}
    - USB: class: cdc-wdm: Fix CPU lockup caused by excessive log messages (Alan Stern) [Orabug: 36835708]
    {CVE-2024-40904}
    - nilfs2: fix nilfs_empty_dir() misjudgment and long loop on I/O errors (Ryusuke Konishi) [Orabug:
    36774645] {CVE-2024-39469}
    - i2c: acpi: Unbind mux adapters before delete (Hamish Martin) [Orabug: 36774617] {CVE-2024-39362}
    - mmc: davinci: Don't strip remove function when driver is builtin (Uwe Kleine-Konig) [Orabug: 36809300]
    {CVE-2024-39484}
    - ftrace: Fix possible use-after-free issue in ftrace_location() (Zheng Yejian) [Orabug: 36753573]
    {CVE-2024-38588}
    - Bluetooth: qca: fix info leak when fetching fw build id (Johan Hovold) [Orabug: 36683103]
    {CVE-2024-36032}
    - usb: gadget: f_fs: Fix race between aio_cancel() and AIO request complete (Wesley Cheng) [Orabug:
    36683254] {CVE-2024-36894}
    - ipv6: fix possible race in __fib6_drop_pcpu_from() (Eric Dumazet) [Orabug: 36835713] {CVE-2024-40905}
    - net/sched: taprio: always validate TCA_TAPRIO_ATTR_PRIOMAP (Eric Dumazet) [Orabug: 36748168]
    {CVE-2024-36974}
    - net: sched: sch_multiq: fix possible OOB write in multiq_tune() (Hangyu Hua) [Orabug: 36748175]
    {CVE-2024-36978}
    - bpf: Set run context for rawtp test_run callback (Jiri Olsa) [Orabug: 36835722] {CVE-2024-40908}
    - wifi: iwlwifi: mvm: don't read past the mfuart notifcation (Emmanuel Grumbach) [Orabug: 36835807]
    {CVE-2024-40941}
    - wifi: iwlwifi: mvm: check n_ssids before accessing the ssids (Miri Korenblit) [Orabug: 36835779]
    {CVE-2024-40929}
    - wifi: cfg80211: Lock wiphy in cfg80211_get_station (Remi Pommarel) [Orabug: 36835729] {CVE-2024-40911}
    - wifi: mac80211: Fix deadlock in ieee80211_sta_ps_deliver_wakeup() (Remi Pommarel) [Orabug: 36835734]
    {CVE-2024-40912}

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2024-12618.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-42154");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:8::UEKR7");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:8::developer_UEKR7");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:9::UEKR7");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:9::developer_UEKR7");
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
  script_set_attribute(attribute:"stig_severity", value:"I");
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
  var fixed_uptrack_levels = ['5.15.0-210.163.7.el8uek', '5.15.0-210.163.7.el9uek'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2024-12618');
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
    {'reference':'bpftool-5.15.0-210.163.7.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'bpftool-5.15.0'},
    {'reference':'kernel-uek-5.15.0-210.163.7.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-5.15.0'},
    {'reference':'kernel-uek-container-5.15.0-210.163.7.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-container-5.15.0'},
    {'reference':'kernel-uek-container-debug-5.15.0-210.163.7.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-container-debug-5.15.0'},
    {'reference':'kernel-uek-core-5.15.0-210.163.7.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-core-5.15.0'},
    {'reference':'kernel-uek-debug-5.15.0-210.163.7.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-5.15.0'},
    {'reference':'kernel-uek-debug-core-5.15.0-210.163.7.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-core-5.15.0'},
    {'reference':'kernel-uek-debug-devel-5.15.0-210.163.7.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-5.15.0'},
    {'reference':'kernel-uek-debug-modules-5.15.0-210.163.7.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-modules-5.15.0'},
    {'reference':'kernel-uek-debug-modules-extra-5.15.0-210.163.7.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-modules-extra-5.15.0'},
    {'reference':'kernel-uek-devel-5.15.0-210.163.7.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-5.15.0'},
    {'reference':'kernel-uek-doc-5.15.0-210.163.7.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-5.15.0'},
    {'reference':'kernel-uek-modules-5.15.0-210.163.7.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-modules-5.15.0'},
    {'reference':'kernel-uek-modules-extra-5.15.0-210.163.7.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-modules-extra-5.15.0'},
    {'reference':'bpftool-5.15.0-210.163.7.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'bpftool-5.15.0'},
    {'reference':'kernel-uek-5.15.0-210.163.7.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-5.15.0'},
    {'reference':'kernel-uek-container-5.15.0-210.163.7.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-container-5.15.0'},
    {'reference':'kernel-uek-container-debug-5.15.0-210.163.7.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-container-debug-5.15.0'},
    {'reference':'kernel-uek-core-5.15.0-210.163.7.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-core-5.15.0'},
    {'reference':'kernel-uek-debug-5.15.0-210.163.7.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-5.15.0'},
    {'reference':'kernel-uek-debug-core-5.15.0-210.163.7.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-core-5.15.0'},
    {'reference':'kernel-uek-debug-devel-5.15.0-210.163.7.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-5.15.0'},
    {'reference':'kernel-uek-debug-modules-5.15.0-210.163.7.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-modules-5.15.0'},
    {'reference':'kernel-uek-debug-modules-extra-5.15.0-210.163.7.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-modules-extra-5.15.0'},
    {'reference':'kernel-uek-devel-5.15.0-210.163.7.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-5.15.0'},
    {'reference':'kernel-uek-doc-5.15.0-210.163.7.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-5.15.0'},
    {'reference':'kernel-uek-modules-5.15.0-210.163.7.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-modules-5.15.0'},
    {'reference':'kernel-uek-modules-extra-5.15.0-210.163.7.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-modules-extra-5.15.0'},
    {'reference':'bpftool-5.15.0-210.163.7.el9uek', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'bpftool-5.15.0'},
    {'reference':'kernel-uek-5.15.0-210.163.7.el9uek', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-5.15.0'},
    {'reference':'kernel-uek-container-5.15.0-210.163.7.el9uek', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-container-5.15.0'},
    {'reference':'kernel-uek-container-debug-5.15.0-210.163.7.el9uek', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-container-debug-5.15.0'},
    {'reference':'kernel-uek-core-5.15.0-210.163.7.el9uek', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-core-5.15.0'},
    {'reference':'kernel-uek-debug-5.15.0-210.163.7.el9uek', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-5.15.0'},
    {'reference':'kernel-uek-debug-core-5.15.0-210.163.7.el9uek', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-core-5.15.0'},
    {'reference':'kernel-uek-debug-devel-5.15.0-210.163.7.el9uek', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-5.15.0'},
    {'reference':'kernel-uek-debug-modules-5.15.0-210.163.7.el9uek', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-modules-5.15.0'},
    {'reference':'kernel-uek-debug-modules-extra-5.15.0-210.163.7.el9uek', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-modules-extra-5.15.0'},
    {'reference':'kernel-uek-devel-5.15.0-210.163.7.el9uek', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-5.15.0'},
    {'reference':'kernel-uek-doc-5.15.0-210.163.7.el9uek', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-5.15.0'},
    {'reference':'kernel-uek-modules-5.15.0-210.163.7.el9uek', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-modules-5.15.0'},
    {'reference':'kernel-uek-modules-extra-5.15.0-210.163.7.el9uek', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-modules-extra-5.15.0'},
    {'reference':'bpftool-5.15.0-210.163.7.el9uek', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'bpftool-5.15.0'},
    {'reference':'kernel-uek-5.15.0-210.163.7.el9uek', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-5.15.0'},
    {'reference':'kernel-uek-container-5.15.0-210.163.7.el9uek', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-container-5.15.0'},
    {'reference':'kernel-uek-container-debug-5.15.0-210.163.7.el9uek', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-container-debug-5.15.0'},
    {'reference':'kernel-uek-core-5.15.0-210.163.7.el9uek', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-core-5.15.0'},
    {'reference':'kernel-uek-debug-5.15.0-210.163.7.el9uek', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-5.15.0'},
    {'reference':'kernel-uek-debug-core-5.15.0-210.163.7.el9uek', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-core-5.15.0'},
    {'reference':'kernel-uek-debug-devel-5.15.0-210.163.7.el9uek', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-5.15.0'},
    {'reference':'kernel-uek-debug-modules-5.15.0-210.163.7.el9uek', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-modules-5.15.0'},
    {'reference':'kernel-uek-debug-modules-extra-5.15.0-210.163.7.el9uek', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-modules-extra-5.15.0'},
    {'reference':'kernel-uek-devel-5.15.0-210.163.7.el9uek', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-5.15.0'},
    {'reference':'kernel-uek-doc-5.15.0-210.163.7.el9uek', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-5.15.0'},
    {'reference':'kernel-uek-modules-5.15.0-210.163.7.el9uek', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-modules-5.15.0'},
    {'reference':'kernel-uek-modules-extra-5.15.0-210.163.7.el9uek', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-modules-extra-5.15.0'}
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
