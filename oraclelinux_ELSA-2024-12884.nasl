#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2024-12884.
##

include('compat.inc');

if (description)
{
  script_id(213056);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/17");

  script_cve_id(
    "CVE-2024-26734",
    "CVE-2024-26885",
    "CVE-2024-26921",
    "CVE-2024-40953",
    "CVE-2024-41016",
    "CVE-2024-42229",
    "CVE-2024-44931",
    "CVE-2024-46849",
    "CVE-2024-46853",
    "CVE-2024-46854",
    "CVE-2024-47670",
    "CVE-2024-47671",
    "CVE-2024-47672",
    "CVE-2024-47674",
    "CVE-2024-47679",
    "CVE-2024-47684",
    "CVE-2024-47685",
    "CVE-2024-47692",
    "CVE-2024-47696",
    "CVE-2024-47697",
    "CVE-2024-47698",
    "CVE-2024-47699",
    "CVE-2024-47701",
    "CVE-2024-47709",
    "CVE-2024-47710",
    "CVE-2024-47712",
    "CVE-2024-47713",
    "CVE-2024-47723",
    "CVE-2024-47737",
    "CVE-2024-47740",
    "CVE-2024-47742",
    "CVE-2024-47747",
    "CVE-2024-47749",
    "CVE-2024-47756",
    "CVE-2024-47757",
    "CVE-2024-49851",
    "CVE-2024-49860",
    "CVE-2024-49867",
    "CVE-2024-49868",
    "CVE-2024-49877",
    "CVE-2024-49878",
    "CVE-2024-49879",
    "CVE-2024-49882",
    "CVE-2024-49883",
    "CVE-2024-49892",
    "CVE-2024-49894",
    "CVE-2024-49896",
    "CVE-2024-49900",
    "CVE-2024-49902",
    "CVE-2024-49903",
    "CVE-2024-49924",
    "CVE-2024-49938",
    "CVE-2024-49944",
    "CVE-2024-49948",
    "CVE-2024-49949",
    "CVE-2024-49952",
    "CVE-2024-49955",
    "CVE-2024-49957",
    "CVE-2024-49959",
    "CVE-2024-49962",
    "CVE-2024-49963",
    "CVE-2024-49965",
    "CVE-2024-49966",
    "CVE-2024-49967",
    "CVE-2024-49973",
    "CVE-2024-49981",
    "CVE-2024-49982",
    "CVE-2024-49985",
    "CVE-2024-49995",
    "CVE-2024-49997",
    "CVE-2024-50006",
    "CVE-2024-50007",
    "CVE-2024-50008",
    "CVE-2024-50024",
    "CVE-2024-50033",
    "CVE-2024-50035",
    "CVE-2024-50039",
    "CVE-2024-50040",
    "CVE-2024-50044",
    "CVE-2024-50045",
    "CVE-2024-50059",
    "CVE-2024-50074",
    "CVE-2024-50082",
    "CVE-2024-50089",
    "CVE-2024-50096",
    "CVE-2024-50099",
    "CVE-2024-50116",
    "CVE-2024-50117",
    "CVE-2024-50127",
    "CVE-2024-50131",
    "CVE-2024-50134",
    "CVE-2024-50142",
    "CVE-2024-50143",
    "CVE-2024-50148",
    "CVE-2024-50150",
    "CVE-2024-50151",
    "CVE-2024-50167",
    "CVE-2024-50168",
    "CVE-2024-50171",
    "CVE-2024-50179",
    "CVE-2024-50180",
    "CVE-2024-50184",
    "CVE-2024-50194",
    "CVE-2024-50195",
    "CVE-2024-50199",
    "CVE-2024-50202",
    "CVE-2024-50205",
    "CVE-2024-50210",
    "CVE-2024-50218",
    "CVE-2024-50228",
    "CVE-2024-50229",
    "CVE-2024-50230",
    "CVE-2024-50233",
    "CVE-2024-50234",
    "CVE-2024-50236",
    "CVE-2024-50237",
    "CVE-2024-50251",
    "CVE-2024-50262",
    "CVE-2024-53057",
    "CVE-2024-53059",
    "CVE-2024-53060",
    "CVE-2024-53097"
  );

  script_name(english:"Oracle Linux 7 / 8 : Unbreakable Enterprise kernel (ELSA-2024-12884)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 7 / 8 host has packages installed that are affected by multiple vulnerabilities as referenced in
the ELSA-2024-12884 advisory.

    - devlink: fix possible use-after-free and memory leaks in devlink_init() (Vasiliy Kovalev)  [Orabug:
    37284641]  {CVE-2024-26734}
    - mm: avoid leaving partial pfn mappings around in error case (Linus Torvalds)  [Orabug: 37174200]
    {CVE-2024-47674}
    - mm: add remap_pfn_range_notrack (Christoph Hellwig)  [Orabug: 37174200]  {CVE-2024-47674}
    - mm/memory.c: make remap_pfn_range() reject unaligned addr (Alex Zhang)  [Orabug: 37174200]
    {CVE-2024-47674}
    - mm: fix ambiguous comments for better code readability (chenqiwu)  [Orabug: 37174200]  {CVE-2024-47674}
    - mm: clarify a confusing comment for remap_pfn_range() (WANG Wenhu)  [Orabug: 37174200]  {CVE-2024-47674}
    - drm/amdgpu: prevent NULL pointer dereference if ATIF is not supported (Antonio Quartulli) [Orabug:
    37304754] {CVE-2024-53060}
    - mm: krealloc: Fix MTE false alarm in __do_krealloc (Qun-Wei Lin) [Orabug: 37331939] {CVE-2024-53097}
    - mm: shmem: fix data-race in shmem_getattr() (Jeongjun Park) [Orabug: 37268581] {CVE-2024-50228}
    - nilfs2: fix kernel bug due to missing clearing of checked flag (Ryusuke Konishi) [Orabug: 37268589]
    {CVE-2024-50230}
    - ocfs2: pass u64 to ocfs2_truncate_inline maybe overflow (Edward Adam Davis) [Orabug: 37268564]
    {CVE-2024-50218}
    - nilfs2: fix potential deadlock with newly created symlinks (Ryusuke Konishi) [Orabug: 37268585]
    {CVE-2024-50229}
    - staging: iio: frequency: ad9832: fix division by zero in ad9832_calc_freqreg() (Zicheng Qu) [Orabug:
    37268598] {CVE-2024-50233}
    - wifi: iwlegacy: Clear stale interrupts before resuming device (Ville Syrjala) [Orabug: 37268603]
    {CVE-2024-50234}
    - wifi: ath10k: Fix memory leak in management tx (Manikanta Pubbisetty) [Orabug: 37268611]
    {CVE-2024-50236}
    - wifi: mac80211: do not pass a stopped vif to the driver in .get_txpower (Felix Fietkau) [Orabug:
    37268614] {CVE-2024-50237}
    - netfilter: nft_payload: sanitize offset and length before calling skb_checksum() (Pablo Neira Ayuso)
    [Orabug: 37268671] {CVE-2024-50251}
    - bpf: Fix out-of-bounds write in trie_get_next_key() (Byeonguk Jeong) [Orabug: 37268703] {CVE-2024-50262}
    - net/sched: stop qdisc_tree_reduce_backlog on TC_H_ROOT (Pedro Tammela) [Orabug: 37304741]
    {CVE-2024-53057}
    - wifi: iwlwifi: mvm: Fix response handling in iwl_mvm_send_recovery_cmd() (Daniel Gabay) [Orabug:
    37304750] {CVE-2024-53059}
    - xfrm: validate new SA's prefixlen using SA family when sel.family is unset (Sabrina Dubroca) [Orabug:
    37264076] {CVE-2024-50142}
    - nilfs2: fix kernel bug due to missing clearing of buffer delay flag (Ryusuke Konishi) [Orabug: 37252378]
    {CVE-2024-50116}
    - drm/amd: Guard against bad data for ATIF ACPI method (Mario Limonciello) [Orabug: 37252384]
    {CVE-2024-50117}
    - ALSA: firewire-lib: Avoid division by zero in apply_constraint_to_size() (Andrey Shumilin) [Orabug:
    37264275] {CVE-2024-50205}
    - posix-clock: posix-clock: Fix unbalanced locking in pc_clock_settime() (Jinjie Ruan) [Orabug: 37304479]
    {CVE-2024-50210}
    - net: sched: fix use-after-free in taprio_change() (Dmitry Antipov) [Orabug: 37252408] {CVE-2024-50127}
    - be2net: fix potential memory leak in be_xmit() (Wang Hai) [Orabug: 37264144] {CVE-2024-50167}
    - net/sun3_82586: fix potential memory leak in sun3_82586_send_packet() (Wang Hai) [Orabug: 37264150]
    {CVE-2024-50168}
    - tracing: Consider the NULL character when validating the event length (Leo Yan) [Orabug: 37252416]
    {CVE-2024-50131}
    - udf: fix uninit-value use in udf_get_fileshortad (Gianfranco Trad) [Orabug: 37264081] {CVE-2024-50143}
    - drm/vboxvideo: Replace fake VLA at end of vbva_mouse_pointer_shape with real VLA (Hans de Goede)
    [Orabug: 37252421] {CVE-2024-50134}
    - arm64: probes: Fix uprobes for big-endian kernels (Mark Rutland) [Orabug: 37264237] {CVE-2024-50194}
    - Bluetooth: bnep: fix wild-memory-access in proto_unregister (Ye Bin) [Orabug: 37264097] {CVE-2024-50148}
    - usb: typec: altmode should keep reference to parent (Thadeu Lima de Souza Cascardo) [Orabug: 37264103]
    {CVE-2024-50150}
    - smb: client: fix OOBs when building SMB2_IOCTL request (Paulo Alcantara) [Orabug: 37264108]
    {CVE-2024-50151}
    - net: systemport: fix potential memory leak in bcm_sysport_xmit() (Wang Hai) [Orabug: 37264157]
    {CVE-2024-50171}
    - nilfs2: propagate directory read errors from nilfs_find_entry() (Ryusuke Konishi) [Orabug: 37264267]
    {CVE-2024-50202}
    - parport: Proper fix for array out-of-bounds access (Takashi Iwai) [Orabug: 37227436] {CVE-2024-50074}
    - blk-rq-qos: fix crash on rq_qos_wait vs. rq_qos_wake_function race (Omar Sandoval) [Orabug: 37227404]
    {CVE-2024-50082}
    - KVM: Fix a data race on last_boosted_vcpu in kvm_vcpu_on_spin() (Breno Leitao) [Orabug: 36835837]
    {CVE-2024-40953}
    - mm/swapfile: skip HugeTLB pages for unuse_vma (Liu Shixin) [Orabug: 37264257] {CVE-2024-50199}
    - arm64: probes: Remove broken LDR (literal) uprobe support (Mark Rutland) [Orabug: 37252317]
    {CVE-2024-50099}
    - posix-clock: Fix missing timespec64 check in pc_clock_settime() (Jinjie Ruan) [Orabug: 37264242]
    {CVE-2024-50195}
    - nouveau/dmem: Fix vulnerability in migrate_to_ram upon copy error (Yonatan Maman) [Orabug: 37252308]
    {CVE-2024-50096}
    - net: Fix an unsafe loop on the list (Anastasia Kovaleva) [Orabug: 37206409] {CVE-2024-50024}
    - resource: fix region_intersects() vs add_memory_driver_managed() (Huang Ying) [Orabug: 37200931]
    {CVE-2024-49878}
    - slip: make slhc_remember() more robust against malicious packets (Eric Dumazet) [Orabug: 37206429]
    {CVE-2024-50033}
    - ppp: fix ppp_async_encode() illegal access (Eric Dumazet) [Orabug: 37206435] {CVE-2024-50035}
    - net/sched: accept TCA_STAB only for root qdisc (Eric Dumazet) [Orabug: 37206457] {CVE-2024-50039}
    - igb: Do not bring the device up after non-fatal error (Mohamed Khalfella) [Orabug: 37206464]
    {CVE-2024-50040}
    - Bluetooth: RFCOMM: FIX possible deadlock in rfcomm_sk_state_change (Luiz Augusto von Dentz) [Orabug:
    37206474] {CVE-2024-50044}
    - netfilter: br_netfilter: fix panic with metadata_dst skb (Andy Roulin) [Orabug: 37206482]
    {CVE-2024-50045}
    - fbdev: sisfb: Fix strbuf array overflow (Andrey Shumilin) [Orabug: 37264186] {CVE-2024-50180}
    - virtio_pmem: Check device status before requesting flush (Philip Chen) [Orabug: 37264205]
    {CVE-2024-50184}
    - ntb: ntb_hw_switchtec: Fix use after free vulnerability in switchtec_ntb_remove due to race condition
    (Kaixin Wang) [Orabug: 37206542] {CVE-2024-50059}
    - unicode: Don't special case ignorable code points (Gabriel Krisman Bertazi) [Orabug: 37252274]
    {CVE-2024-50089}
    - ACPI: battery: Fix possible crash when unregistering a battery hook (Armin Wolf) [Orabug: 37206092]
    {CVE-2024-49955}
    - r8169: add tally counter fields added with RTL8125 (Heiner Kallweit) [Orabug: 37206183] {CVE-2024-49973}
    - btrfs: wait for fixup workers before stopping cleaner kthread during umount (Filipe Manana) [Orabug:
    37200897] {CVE-2024-49867}
    - btrfs: fix a NULL pointer dereference when failed to start a new trasacntion (Qu Wenruo) [Orabug:
    37200903] {CVE-2024-49868}
    - media: venus: fix use after free bug in venus_remove due to race condition (Zheng Wang) [Orabug:
    37206210] {CVE-2024-49981}
    - aoe: fix the potential use-after-free problem in more places (Chun-Yi Lee) [Orabug: 37206642]
    {CVE-2024-49982}
    - ocfs2: fix possible null-ptr-deref in ocfs2_set_buffer_uptodate (Lizhi Xu) [Orabug: 37200926]
    {CVE-2024-49877}
    - ocfs2: fix null-ptr-deref when journal load failed. (Julian Sun) [Orabug: 37206097] {CVE-2024-49957}
    - ocfs2: remove unreasonable unlock in ocfs2_read_blocks (Lizhi Xu) [Orabug: 37206137] {CVE-2024-49965}
    - ocfs2: cancel dqi_sync_work before freeing oinfo (Joseph Qi) [Orabug: 37206141] {CVE-2024-49966}
    - jbd2: stop waiting for space when jbd2_cleanup_journal_tail() returns error (Baokun Li) [Orabug:
    37206109] {CVE-2024-49959}
    - drm: omapdrm: Add missing check for alloc_ordered_workqueue (Ma Ke) [Orabug: 37200935] {CVE-2024-49879}
    in of_msi_get_domain (Andrew Jones)
    - ext4: fix double brelse() the buffer of the extents path (Baokun Li) [Orabug: 37200948] {CVE-2024-49882}
    - ext4: aovid use-after-free in ext4_ext_insert_extent() (Baokun Li) [Orabug: 37200954] {CVE-2024-49883}
    - ext4: no need to continue when the number of entries is 1 (Edward Adam Davis) [Orabug: 37206147]
    {CVE-2024-49967}
    - i2c: stm32f7: Do not prepare/unprepare clock during runtime suspend/resume (Marek Vasut) [Orabug:
    37206220] {CVE-2024-49985}
    - ext4: fix i_data_sem unlock order in ext4_ind_migrate() (Artem Sadovnikov) [Orabug: 37206323]
    {CVE-2024-50006}
    - drm/amd/display: Initialize get_bytes_per_element's default to 1 (Alex Hung) [Orabug: 37205727]
    {CVE-2024-49892}
    - drm/amd/display: Fix index out of bounds in degamma hardware format translation (Srinivasan Shanmugam)
    [Orabug: 37205740] {CVE-2024-49894}
    - drm/amd/display: Check stream before comparing them (Alex Hung) [Orabug: 37205752] {CVE-2024-49896}
    - jfs: Fix uninit-value access of new_ea in ea_buffer (Zhao Mengmeng) [Orabug: 37205778] {CVE-2024-49900}
    - jfs: check if leafidx greater than num leaves per dmap tree (Edward Adam Davis) [Orabug: 37205790]
    {CVE-2024-49902}
    - jfs: Fix uaf in dbFreeBits (Edward Adam Davis) [Orabug: 37205795] {CVE-2024-49903}
    - fbdev: pxafb: Fix possible use after free in pxafb_task() (Kaixin Wang) [Orabug: 37205936]
    {CVE-2024-49924}
    - ALSA: asihpi: Fix potential OOB array access (Takashi Iwai) [Orabug: 37206328] {CVE-2024-50007}
    - wifi: mwifiex: Fix memcpy() field-spanning write warning in mwifiex_cmd_802_11_scan_ext() (Gustavo A. R.
    Silva) [Orabug: 37206333] {CVE-2024-50008}
    - tipc: guard against string buffer overrun (Simon Horman) [Orabug: 37206278] {CVE-2024-49995}
    - ACPICA: check null return of ACPI_ALLOCATE_ZEROED() in acpi_db_convert_to_package() (Pei Xiao) [Orabug:
    37206124] {CVE-2024-49962}
    - wifi: ath9k_htc: Use __skb_set_length() for resetting urb before resubmit (Toke Hoiland-Jorgensen)
    [Orabug: 37206029] {CVE-2024-49938}
    - f2fs: Require FMODE_WRITE for atomic write ioctls (Jann Horn) [Orabug: 37200794] {CVE-2024-47740}
    - sctp: set sk_state back to CLOSED if autobind fails in sctp_listen_start (Xin Long) [Orabug: 37206051]
    {CVE-2024-49944}
    - net: add more sanity checks to qdisc_pkt_len_init() (Eric Dumazet) [Orabug: 37206064] {CVE-2024-49948}
    - net: avoid potential underflow in qdisc_pkt_len_init() with UFO (Eric Dumazet) [Orabug: 37206070]
    {CVE-2024-49949}
    - net: ethernet: lantiq_etop: fix memory disclosure (Aleksander Jan Bajkowski) [Orabug: 37206289]
    {CVE-2024-49997}
    - netfilter: nf_tables: prevent nf_skb_duplicated corruption (Eric Dumazet) [Orabug: 37206081]
    {CVE-2024-49952}
    - ceph: remove the incorrect Fw reference check when dirtying pages (Xiubo Li) [Orabug: 37264181]
    {CVE-2024-50179}
    - mailbox: bcm2835: Fix timeout during suspend mode (Stefan Wahren) [Orabug: 37206130] {CVE-2024-49963}
    - ASoC: meson: axg-card: fix 'use-after-free' (Arseniy Krasnov) [Orabug: 37116540] {CVE-2024-46849}
    - vfs: fix race between evice_inodes() and find_inode()&iput() (Julian Sun) [Orabug: 37200604]
    {CVE-2024-47679}
    - ACPI: sysfs: validate return type of _STR method (Thomas Weissschuh) [Orabug: 37200878] {CVE-2024-49860}
    - firmware_loader: Block path traversal (Jann Horn) [Orabug: 37200802] {CVE-2024-47742}
    - crypto: aead,cipher - zeroize key buffer after use (Hailey Mothershead) [Orabug: 36898014]
    {CVE-2024-42229}
    - tcp: check skb is non-NULL in tcp_rto_delta_us() (Josh Hunt) [Orabug: 37200624] {CVE-2024-47684}
    - net: seeq: Fix use after free vulnerability in ether3 Driver Due to Race Condition (Kaixin Wang)
    [Orabug: 37200818] {CVE-2024-47747}
    - netfilter: nf_reject_ipv6: fix nf_reject_ip6_tcphdr_put() (Eric Dumazet) [Orabug: 37200630]
    {CVE-2024-47685}
    - nfsd: return -EINVAL when namelen is 0 (Li Lingfeng) [Orabug: 37200650] {CVE-2024-47692}
    - nfsd: call cache_put if xdr_reserve_space returns NULL (Guoqing Jiang) [Orabug: 37200783]
    {CVE-2024-47737}
    - RDMA/cxgb4: Added NULL check for lookup_atid (Mikhail Lobanov) [Orabug: 37200824] {CVE-2024-47749}
    - RDMA/iwcm: Fix WARNING:at_kernel/workqueue.c:#check_flush_dependency (Zhu Yanjun) [Orabug: 37205521]
    {CVE-2024-47696}
    - PCI: keystone: Fix if-statement expression in ks_pcie_quirk() (Dan Carpenter) [Orabug: 37205560]
    {CVE-2024-47756}
    - drivers: media: dvb-frontends/rtl2830: fix an out-of-bounds write error (Junlin Li) [Orabug: 37200662]
    {CVE-2024-47697}
    - drivers: media: dvb-frontends/rtl2832: fix an out-of-bounds write error (Junlin Li) [Orabug: 37200669]
    {CVE-2024-47698}
    - nilfs2: fix potential oob read in nilfs_btree_check_delete() (Ryusuke Konishi) [Orabug: 37200843]
    {CVE-2024-47757}
    - nilfs2: fix potential null-ptr-deref in nilfs_btree_insert() (Ryusuke Konishi) [Orabug: 37200676]
    {CVE-2024-47699}
    - ext4: avoid OOB when system.data xattr changes underneath the filesystem (Thadeu Lima de Souza Cascardo)
    [Orabug: 37200682] {CVE-2024-47701}
    - tpm: Clean up TPM space after command failure (Jonathan McDowell) [Orabug: 37200851] {CVE-2024-49851}
    - jfs: fix out-of-bounds in dbNextAG() and diAlloc() (Jeongjun Park) [Orabug: 37200741] {CVE-2024-47723}
    - can: bcm: Clear bo->bcm_proc_read after remove_proc_entry(). (Kuniyuki Iwashima) [Orabug: 37205476]
    {CVE-2024-47709}
    - sock_map: Add a cond_resched() in sock_hash_free() (Eric Dumazet) [Orabug: 37200715] {CVE-2024-47710}
    - wifi: wilc1000: fix potential RCU dereference issue in wilc_parse_join_bss_param (Jiawei Ye) [Orabug:
    37205503] {CVE-2024-47712}
    - wifi: mac80211: use two-phase skb reclamation in ieee80211_do_stop() (Dmitry Antipov) [Orabug: 37200721]
    {CVE-2024-47713}
    - USB: usbtmc: prevent kernel-usb-infoleak (Edward Adam Davis) [Orabug: 37159778] {CVE-2024-47671}
    - bpf: Fix DEVMAP_HASH overflow check on 32-bit arches (Toke Hoiland-Jorgensen) [Orabug: 36544917]
    {CVE-2024-26885}
    - inet: inet_defrag: prevent sk release while still in use (Florian Westphal) [Orabug: 36545060]
    {CVE-2024-26921}
    - gpio: prevent potential speculation leaks in gpio_device_get_desc() (Hagar Hemdan) [Orabug: 36993135]
    {CVE-2024-44931}
    - ocfs2: strict bound check before memcmp in ocfs2_xattr_find_entry() (Ferry Meng) [Orabug: 36891661]
    {CVE-2024-41016}
    - ocfs2: add bounds checking to ocfs2_xattr_find_entry() (Ferry Meng) [Orabug: 37159773] {CVE-2024-47670}
    - wifi: iwlwifi: mvm: don't wait for tx queues if firmware is dead (Emmanuel Grumbach) [Orabug: 37159781]
    {CVE-2024-47672}
    - spi: nxp-fspi: fix the KASAN report out-of-bounds bug (Han Xu) [Orabug: 37116548] {CVE-2024-46853}
    - net: dpaa: Pad packets to ETH_ZLEN (Sean Anderson) [Orabug: 37116551] {CVE-2024-46854}
    - ocfs2: reserve space for inline xattr before attaching reflink tree (Gautham Ananthakrishna)  [Orabug:
    37199020] {CVE-2024-49958}
    - vhost/scsi: null-ptr-dereference in vhost_scsi_get_req() (Haoran Zhang)  [Orabug: 37137548]
    {CVE-2024-49863}
    - mm/hugetlb: fix DEBUG_LOCKS_WARN_ON(1) when dissolve_free_hugetlb_folio() (Miaohe Lin)  [Orabug:
    36683094]  {CVE-2024-36028}
    - rtmutex: Drop rt_mutex::wait_lock before scheduling (Roland Xu) [Orabug: 37116446] {CVE-2024-46829}
    - nvmet-tcp: fix kernel crash if commands allocation fails (Maurizio Lombardi) [Orabug: 37074465]
    {CVE-2024-46737}
    - arm64: acpi: Harden get_cpu_for_acpi_id() against missing CPU entry (Jonathan Cameron) [Orabug:
    37116413] {CVE-2024-46822}
    - nilfs2: protect references to superblock parameters exposed in sysfs (Ryusuke Konishi) [Orabug:
    37074677] {CVE-2024-46780}
    - uio_hv_generic: Fix kernel NULL pointer dereference in hv_uio_rescind (Saurabh Sengar) [Orabug:
    37074473] {CVE-2024-46739}
    - binder: fix UAF caused by offsets overwrite (Carlos Llamas) [Orabug: 37074477] {CVE-2024-46740}
    - staging: iio: frequency: ad9834: Validate frequency parameter value (Aleksandr Mishin) [Orabug:
    37159728] {CVE-2024-47663}
    - lib/generic-radix-tree.c: Fix rare race in __genradix_ptr_alloc() (Kent Overstreet) [Orabug: 37159757]
    {CVE-2024-47668}
    - of/irq: Prevent device address out-of-bounds read in interrupt map walk (Stefan Wiehler) [Orabug:
    37074488] {CVE-2024-46743}
    - Squashfs: sanity check symbolic link size (Phillip Lougher) [Orabug: 37074495] {CVE-2024-46744}
    - Input: uinput - reject requests with unreasonable number of slots (Dmitry Torokhov) [Orabug: 37074503]
    {CVE-2024-46745}
    - HID: cougar: fix slab-out-of-bounds Read in cougar_report_fixup (Camila Alvarez) [Orabug: 37074513]
    {CVE-2024-46747}
    - PCI: Add missing bridge lock to pci_bus_lock() (Dan Williams) [Orabug: 37074532] {CVE-2024-46750}
    - btrfs: clean up our handling of refs == 0 in snapshot delete (Josef Bacik) [Orabug: 37116494]
    {CVE-2024-46840}
    - wifi: mwifiex: Do not return unused priv in mwifiex_get_priv_by_id() (Sascha Hauer) [Orabug: 37074561]
    {CVE-2024-46755}
    - hwmon: (w83627ehf) Fix underflows seen when writing limit attributes (Guenter Roeck) [Orabug: 37074566]
    {CVE-2024-46756}
    - hwmon: (nct6775-core) Fix underflows seen when writing limit attributes (Guenter Roeck) [Orabug:
    37074571] {CVE-2024-46757}
    - hwmon: (lm95234) Fix underflows seen when writing limit attributes (Guenter Roeck) [Orabug: 37074579]
    {CVE-2024-46758}
    - hwmon: (adc128d818) Fix underflows seen when writing limit attributes (Guenter Roeck) [Orabug: 37074584]
    {CVE-2024-46759}
    - pci/hotplug/pnv_php: Fix hotplug driver crash on Powernv (Krishna Kumar) [Orabug: 37074595]
    {CVE-2024-46761}
    - um: line: always fill *error_out in setup_one_line() (Johannes Berg) [Orabug: 37116518] {CVE-2024-46844}
    - tcp_bpf: fix return value of tcp_bpf_sendmsg() (Cong Wang) [Orabug: 37074693] {CVE-2024-46783}
    - can: bcm: Remove proc entry when dev is unregistered. (Kuniyuki Iwashima) [Orabug: 37074625]
    {CVE-2024-46771}
    - PCI: keystone: Add workaround for Errata #i2037 (AM65x SR 1.0) (Kishon Vijay Abraham I) [Orabug:
    37159750] {CVE-2024-47667}
    - udf: Avoid excessive partition lengths (Jan Kara) [Orabug: 37074665] {CVE-2024-46777}
    - nilfs2: fix state management in error path of log writing function (Ryusuke Konishi) [Orabug: 37159765]
    {CVE-2024-47669}
    - nilfs2: fix missing cleanup on rollforward recovery error (Ryusuke Konishi) [Orabug: 37074684]
    {CVE-2024-46781}
    - sched: sch_cake: fix bulk flow accounting logic for host fairness (Toke Hoiland-Jorgensen) [Orabug:
    37116443] {CVE-2024-46828}
    - ila: call nf_unregister_net_hooks() sooner (Eric Dumazet) [Orabug: 37074689] {CVE-2024-46782}
    - ASoC: dapm: Fix UAF for snd_soc_pcm_runtime object (robelin) [Orabug: 37074722] {CVE-2024-46798}
    - sch/netem: fix use after free in netem_dequeue (Stephen Hemminger) [Orabug: 37074726] {CVE-2024-46800}
    - virtio_net: Fix napi_skb_cache_put warning (Breno Leitao) [Orabug: 36964474] {CVE-2024-43835}
    - block: initialize integrity buffer to zero before writing it to media (Christoph Hellwig) [Orabug:
    36964515] {CVE-2024-43854}
    - drm/amd/display: Skip wbscl_set_scaler_filter if filter is null (Alex Hung) [Orabug: 37073032]
    {CVE-2024-46714}
    - usb: typec: ucsi: Fix null pointer dereference in trace (Abhishek Pandit-Subedi) [Orabug: 37073065]
    {CVE-2024-46719}
    - apparmor: fix possible NULL pointer dereference (Leesoo Ahn) [Orabug: 37073078] {CVE-2024-46721}
    - drm/amdgpu: fix mc_data out-of-bounds read warning (Tim Huang) [Orabug: 37073083] {CVE-2024-46722}
    - drm/amdgpu: fix ucode out-of-bounds read warning (Tim Huang) [Orabug: 37073088] {CVE-2024-46723}
    - drm/amd/display: Check num_valid_sets before accessing reader_wm_sets[] (Alex Hung) [Orabug: 37116366]
    {CVE-2024-46815}
    - drm/amd/display: Stop amdgpu_dm initialize when stream nums greater than 6 (Hersen Wu) [Orabug:
    37116376] {CVE-2024-46817}
    - drm/amd/display: Check gpio_id before used as array index (Alex Hung) [Orabug: 37116385]
    {CVE-2024-46818}
    - scsi: aacraid: Fix double-free on probe failure (Ben Hutchings) [Orabug: 37070700] {CVE-2024-46673}
    - usb: dwc3: st: fix probed platform device ref count on probe error path (Krzysztof Kozlowski) [Orabug:
    37070705] {CVE-2024-46674}
    - usb: dwc3: core: Prevent USB core invalid event buffer address access (Selvarasu Ganesan) [Orabug:
    37070710] {CVE-2024-46675}
    - nfc: pn533: Add poll mod list filling check (Aleksandr Mishin) [Orabug: 37070717] {CVE-2024-46676}
    - gtp: fix a potential NULL pointer dereference (Cong Wang) [Orabug: 37070722] {CVE-2024-46677}
    - ethtool: check device is present when getting link settings (Jamie Bainbridge) [Orabug: 37070728]
    {CVE-2024-46679}
    - cgroup/cpuset: Prevent UAF in proc_cpuset_show() (Chen Ridong) [Orabug: 36964510] {CVE-2024-43853}
    - ata: libata-core: Fix null pointer dereference on error (Niklas Cassel) [Orabug: 36897457]
    {CVE-2024-41098}
    - drm/amdkfd: don't allow mapping the MMIO HDP page with large pages (Alex Deucher) [Orabug: 36867631]
    {CVE-2024-41011}
    - pinctrl: single: fix potential NULL dereference in pcs_get_function() (Ma Ke) [Orabug: 37070744]
    {CVE-2024-46685}
    - drm/amdgpu: Using uninitialized value *size when calling amdgpu_vce_cs_reloc (Jesse Zhang) [Orabug:
    36898009] {CVE-2024-42228}
    (Alexander Lobakin)
    - Input: MT - limit max slots (Tetsuo Handa) [Orabug: 37029137] {CVE-2024-45008}
    - Bluetooth: hci_ldisc: check HCI_UART_PROTO_READY flag in HCIUARTGETPROTO (Lee, Chun-Yi) [Orabug:
    36654191] {CVE-2023-31083}
    - Bluetooth: MGMT: Add error handling to pair_device() (Griffin Kroah-Hartman) [Orabug: 36992976]
    {CVE-2024-43884}
    - mmc: mmc_test: Fix NULL dereference on allocation failure (Dan Carpenter) [Orabug: 37070691]
    {CVE-2024-45028}
    - ipv6: prevent UAF in ip6_send_skb() (Eric Dumazet) [Orabug: 37029076] {CVE-2024-44987}
    - netem: fix return value if duplicate enqueue fails (Stephen Hemminger) [Orabug: 37070660]
    {CVE-2024-45016}
    - net: dsa: mv88e6xxx: Fix out-of-bound access (Joseph Huang) [Orabug: 37029082] {CVE-2024-44988}
    - kcm: Serialise kcm_sendmsg() for the same socket. (Kuniyuki Iwashima) [Orabug: 37013761]
    {CVE-2024-44946}
    - gtp: pull network headers in gtp_dev_xmit() (Eric Dumazet) [Orabug: 37029111] {CVE-2024-44999}
    - net: hns3: fix a deadlock problem when config TC during resetting (Jie Wang) [Orabug: 37029098]
    {CVE-2024-44995}
    - atm: idt77252: prevent use after free in dequeue_rx() (Dan Carpenter) [Orabug: 37029105]
    {CVE-2024-44998}
    - memcg_write_event_control(): fix a user-triggerable oops (Al Viro) [Orabug: 37070672] {CVE-2024-45021}
    - fix bitmap corruption on close_range() with CLOSE_RANGE_UNSHARE (Al Viro) [Orabug: 37070680]
    {CVE-2024-45025}
    - vfs: Don't evict inode under the inode lru traversing context (Zhihao Cheng) [Orabug: 37029119]
    {CVE-2024-45003}
    - s390/dasd: fix error recovery leading to data corruption on ESE devices (Stefan Haberland) [Orabug:
    37070687] {CVE-2024-45026}
    - xhci: Fix Panther point NULL pointer deref at full-speed re-enumeration (Mathias Nyman) [Orabug:
    37029125] {CVE-2024-45006}
    - fuse: Initialize beyond-EOF page contents before setting uptodate (Jann Horn) [Orabug: 37017951]
    {CVE-2024-44947}
    - wireguard: netlink: check for dangling peer via is_dead instead of empty list (Jason A. Donenfeld)
    [Orabug: 36596766]  {CVE-2024-26951}

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2024-12884.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-47685");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/12/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:7::UEKR6");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:8::UEKR6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8:10:baseos_patch");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8::baseos_latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-container");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-container-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python-perf");
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
if (! preg(pattern:"^(7|8)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 7 / 8', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var machine_uptrack_level = get_one_kb_item('Host/uptrack-uname-r');
if (machine_uptrack_level)
{
  var trimmed_uptrack_level = ereg_replace(string:machine_uptrack_level, pattern:"\.(x86_64|i[3-6]86|aarch64)$", replace:'');
  var fixed_uptrack_levels = ['5.4.17-2136.338.4.1.el7uek', '5.4.17-2136.338.4.1.el8uek'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2024-12884');
    }
  }
  __rpm_report = 'Running KSplice level of ' + trimmed_uptrack_level + ' does not meet the minimum fixed level of ' + join(fixed_uptrack_levels, sep:' / ') + ' for this advisory.\n\n';
}

var kernel_major_minor = get_kb_item('Host/uname/major_minor');
if (empty_or_null(kernel_major_minor)) exit(1, 'Unable to determine kernel major-minor level.');
var expected_kernel_major_minor = '5.4';
if (kernel_major_minor != expected_kernel_major_minor)
  audit(AUDIT_OS_NOT, 'running kernel level ' + expected_kernel_major_minor + ', it is running kernel level ' + kernel_major_minor);

var pkgs = [
    {'reference':'kernel-uek-5.4.17-2136.338.4.1.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-5.4.17'},
    {'reference':'kernel-uek-debug-5.4.17-2136.338.4.1.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-5.4.17'},
    {'reference':'kernel-uek-debug-devel-5.4.17-2136.338.4.1.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-5.4.17'},
    {'reference':'kernel-uek-devel-5.4.17-2136.338.4.1.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-5.4.17'},
    {'reference':'kernel-uek-doc-5.4.17-2136.338.4.1.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-5.4.17'},
    {'reference':'kernel-uek-tools-5.4.17-2136.338.4.1.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-tools-5.4.17'},
    {'reference':'kernel-uek-tools-libs-5.4.17-2136.338.4.1.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-tools-libs-5.4.17'},
    {'reference':'perf-5.4.17-2136.338.4.1.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'perf-5.4.17'},
    {'reference':'python-perf-5.4.17-2136.338.4.1.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'python-perf-5.4.17'},
    {'reference':'kernel-uek-5.4.17-2136.338.4.1.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-5.4.17'},
    {'reference':'kernel-uek-container-5.4.17-2136.338.4.1.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-container-5.4.17'},
    {'reference':'kernel-uek-container-debug-5.4.17-2136.338.4.1.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-container-debug-5.4.17'},
    {'reference':'kernel-uek-debug-5.4.17-2136.338.4.1.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-5.4.17'},
    {'reference':'kernel-uek-debug-devel-5.4.17-2136.338.4.1.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-5.4.17'},
    {'reference':'kernel-uek-devel-5.4.17-2136.338.4.1.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-5.4.17'},
    {'reference':'kernel-uek-doc-5.4.17-2136.338.4.1.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-5.4.17'},
    {'reference':'kernel-uek-tools-5.4.17-2136.338.4.1.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-tools-5.4.17'},
    {'reference':'kernel-uek-5.4.17-2136.338.4.1.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-5.4.17'},
    {'reference':'kernel-uek-debug-5.4.17-2136.338.4.1.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-5.4.17'},
    {'reference':'kernel-uek-debug-devel-5.4.17-2136.338.4.1.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-5.4.17'},
    {'reference':'kernel-uek-devel-5.4.17-2136.338.4.1.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-5.4.17'},
    {'reference':'kernel-uek-doc-5.4.17-2136.338.4.1.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-5.4.17'},
    {'reference':'kernel-uek-5.4.17-2136.338.4.1.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-5.4.17'},
    {'reference':'kernel-uek-container-5.4.17-2136.338.4.1.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-container-5.4.17'},
    {'reference':'kernel-uek-container-debug-5.4.17-2136.338.4.1.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-container-debug-5.4.17'},
    {'reference':'kernel-uek-debug-5.4.17-2136.338.4.1.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-5.4.17'},
    {'reference':'kernel-uek-debug-devel-5.4.17-2136.338.4.1.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-5.4.17'},
    {'reference':'kernel-uek-devel-5.4.17-2136.338.4.1.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-5.4.17'},
    {'reference':'kernel-uek-doc-5.4.17-2136.338.4.1.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-5.4.17'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel-uek / kernel-uek-container / kernel-uek-container-debug / etc');
}
