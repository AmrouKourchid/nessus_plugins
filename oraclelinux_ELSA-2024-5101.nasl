#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2024-5101.
##

include('compat.inc');

if (description)
{
  script_id(205332);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/02");

  script_cve_id(
    "CVE-2021-46939",
    "CVE-2021-47018",
    "CVE-2021-47257",
    "CVE-2021-47284",
    "CVE-2021-47304",
    "CVE-2021-47373",
    "CVE-2021-47408",
    "CVE-2021-47461",
    "CVE-2021-47468",
    "CVE-2021-47491",
    "CVE-2021-47548",
    "CVE-2021-47579",
    "CVE-2021-47624",
    "CVE-2022-48632",
    "CVE-2022-48743",
    "CVE-2022-48747",
    "CVE-2022-48757",
    "CVE-2023-28746",
    "CVE-2023-52451",
    "CVE-2023-52463",
    "CVE-2023-52469",
    "CVE-2023-52471",
    "CVE-2023-52486",
    "CVE-2023-52530",
    "CVE-2023-52619",
    "CVE-2023-52622",
    "CVE-2023-52623",
    "CVE-2023-52648",
    "CVE-2023-52653",
    "CVE-2023-52658",
    "CVE-2023-52662",
    "CVE-2023-52679",
    "CVE-2023-52707",
    "CVE-2023-52730",
    "CVE-2023-52756",
    "CVE-2023-52762",
    "CVE-2023-52764",
    "CVE-2023-52775",
    "CVE-2023-52777",
    "CVE-2023-52784",
    "CVE-2023-52791",
    "CVE-2023-52796",
    "CVE-2023-52803",
    "CVE-2023-52811",
    "CVE-2023-52832",
    "CVE-2023-52834",
    "CVE-2023-52845",
    "CVE-2023-52847",
    "CVE-2023-52864",
    "CVE-2024-2201",
    "CVE-2024-21823",
    "CVE-2024-25739",
    "CVE-2024-26586",
    "CVE-2024-26614",
    "CVE-2024-26640",
    "CVE-2024-26660",
    "CVE-2024-26669",
    "CVE-2024-26686",
    "CVE-2024-26698",
    "CVE-2024-26704",
    "CVE-2024-26733",
    "CVE-2024-26740",
    "CVE-2024-26772",
    "CVE-2024-26773",
    "CVE-2024-26802",
    "CVE-2024-26810",
    "CVE-2024-26837",
    "CVE-2024-26840",
    "CVE-2024-26843",
    "CVE-2024-26852",
    "CVE-2024-26853",
    "CVE-2024-26870",
    "CVE-2024-26878",
    "CVE-2024-26908",
    "CVE-2024-26921",
    "CVE-2024-26925",
    "CVE-2024-26940",
    "CVE-2024-26958",
    "CVE-2024-26960",
    "CVE-2024-26961",
    "CVE-2024-27010",
    "CVE-2024-27011",
    "CVE-2024-27019",
    "CVE-2024-27020",
    "CVE-2024-27025",
    "CVE-2024-27065",
    "CVE-2024-27388",
    "CVE-2024-27395",
    "CVE-2024-27434",
    "CVE-2024-31076",
    "CVE-2024-33621",
    "CVE-2024-35790",
    "CVE-2024-35801",
    "CVE-2024-35807",
    "CVE-2024-35810",
    "CVE-2024-35814",
    "CVE-2024-35823",
    "CVE-2024-35824",
    "CVE-2024-35847",
    "CVE-2024-35876",
    "CVE-2024-35893",
    "CVE-2024-35896",
    "CVE-2024-35897",
    "CVE-2024-35899",
    "CVE-2024-35900",
    "CVE-2024-35910",
    "CVE-2024-35912",
    "CVE-2024-35924",
    "CVE-2024-35925",
    "CVE-2024-35930",
    "CVE-2024-35937",
    "CVE-2024-35938",
    "CVE-2024-35946",
    "CVE-2024-35947",
    "CVE-2024-35952",
    "CVE-2024-36000",
    "CVE-2024-36005",
    "CVE-2024-36006",
    "CVE-2024-36010",
    "CVE-2024-36016",
    "CVE-2024-36017",
    "CVE-2024-36020",
    "CVE-2024-36025",
    "CVE-2024-36270",
    "CVE-2024-36286",
    "CVE-2024-36489",
    "CVE-2024-36886",
    "CVE-2024-36889",
    "CVE-2024-36896",
    "CVE-2024-36904",
    "CVE-2024-36905",
    "CVE-2024-36917",
    "CVE-2024-36921",
    "CVE-2024-36927",
    "CVE-2024-36929",
    "CVE-2024-36933",
    "CVE-2024-36940",
    "CVE-2024-36941",
    "CVE-2024-36945",
    "CVE-2024-36950",
    "CVE-2024-36954",
    "CVE-2024-36960",
    "CVE-2024-36971",
    "CVE-2024-36978",
    "CVE-2024-36979",
    "CVE-2024-38538",
    "CVE-2024-38555",
    "CVE-2024-38573",
    "CVE-2024-38575",
    "CVE-2024-38596",
    "CVE-2024-38598",
    "CVE-2024-38615",
    "CVE-2024-38627",
    "CVE-2024-39276",
    "CVE-2024-39472",
    "CVE-2024-39476",
    "CVE-2024-39487",
    "CVE-2024-39502",
    "CVE-2024-40927",
    "CVE-2024-40974"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/08/28");

  script_name(english:"Oracle Linux 8 : kernel (ELSA-2024-5101)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2024-5101 advisory.

    - ionic: fix use after netif_napi_del() (CKI Backport Bot) [RHEL-47624] {CVE-2024-39502}
    - ionic: clean interrupt before enabling queue to avoid credit race (CKI Backport Bot) [RHEL-47624]
    {CVE-2024-39502}
    - net/sunrpc: fix reference count leaks in rpc_sysfs_xprt_state_change (CKI Backport Bot) [RHEL-49321]
    {CVE-2021-47624}
    - xhci: Handle TD clearing for multiple streams case (CKI Backport Bot) [RHEL-47882] {CVE-2024-40927}
    - net: openvswitch: Fix Use-After-Free in ovs_ct_exit (cki-backport-bot) [RHEL-36362] {CVE-2024-27395}
    - net: bridge: mst: fix suspicious rcu usage in br_mst_set_state (Ivan Vecera) [RHEL-43721]
    {CVE-2024-36979}
    - net: bridge: mst: pass vlan group directly to br_mst_vlan_set_state (Ivan Vecera) [RHEL-43721]
    {CVE-2024-36979}
    - net: bridge: mst: fix vlan use-after-free (cki-backport-bot) [RHEL-43721] {CVE-2024-36979}
    - irqchip/gic-v3-its: Prevent double free on error (Charles Mirabile) [RHEL-37022] {CVE-2024-35847}
    - irqchip/gic-v3-its: Fix potential VPE leak on error (Charles Mirabile) [RHEL-37744] {CVE-2021-47373}
    - i2c: mlxbf: prevent stack overflow in mlxbf_i2c_smbus_start_transaction() (Charles Mirabile)
    [RHEL-34735] {CVE-2022-48632}
    - iommu/dma: fix zeroing of bounce buffer padding used by untrusted devices (Eder Zulian) [RHEL-36954]
    {CVE-2024-35814}
    - swiotlb: remove alloc_size argument to swiotlb_tbl_map_single() (Eder Zulian) [RHEL-36954]
    {CVE-2024-35814}
    - swiotlb: fix swiotlb_bounce() to do partial sync's correctly (Eder Zulian) [RHEL-36954] {CVE-2024-35814}
    - swiotlb: extend buffer pre-padding to alloc_align_mask if necessary (Eder Zulian) [RHEL-36954]
    {CVE-2024-35814}
    - swiotlb: Reinstate page-alignment for mappings >= PAGE_SIZE (Eder Zulian) [RHEL-36954] {CVE-2024-35814}
    - swiotlb: Fix alignment checks when both allocation and DMA masks are present (Eder Zulian) [RHEL-36954]
    {CVE-2024-35814}
    - swiotlb: Fix double-allocation of slots due to broken alignment handling (Eder Zulian) [RHEL-36954]
    {CVE-2024-35814}
    - genirq/cpuhotplug, x86/vector: Prevent vector leak during CPU offline (cki-backport-bot) [RHEL-44441]
    {CVE-2024-31076}
    - vt: fix unicode buffer corruption when deleting characters (Steve Best) [RHEL-36936] {CVE-2024-35823}
    - usb: typec: altmodes/displayport: create sysfs nodes as driver's default device attribute group (Desnes
    Nunes) [RHEL-36803] {CVE-2024-35790}
    - stm class: Fix a double free in stm_register_device() (Steve Best) [RHEL-44514] {CVE-2024-38627}
    - tls: fix missing memory barrier in tls_init (cki-backport-bot) [RHEL-44471] {CVE-2024-36489}
    - xfs: fix log recovery buffer allocation for the legacy h_size fixup (Bill O'Donnell) [RHEL-46473]
    {CVE-2024-39472}
    - fs/proc: do_task_stat: use sig->stats_lock to gather the threads/children stats (Brian Foster)
    [RHEL-31562] {CVE-2024-26686}
    - fs/proc: do_task_stat: move thread_group_cputime_adjusted() outside of lock_task_sighand() (Brian
    Foster) [RHEL-31562] {CVE-2024-26686}
    - fs/proc: do_task_stat: use __for_each_thread() (Brian Foster) [RHEL-31562] {CVE-2024-26686}
    - exit: Use the correct exit_code in /proc/<pid>/stat (Brian Foster) [RHEL-31562] {CVE-2024-26686}
    - scsi: ibmvfc: Remove BUG_ON in the case of an empty event pool (Ewan D. Milne) [RHEL-38283]
    {CVE-2023-52811}
    - scsi: qla2xxx: Fix double free of fcport (Ewan D. Milne) [RHEL-39549] {CVE-2024-26929}
    - scsi: qla2xxx: Fix double free of the ha->vp_map pointer (Ewan D. Milne) [RHEL-39549] {CVE-2024-26930}
    - scsi: qla2xxx: Fix command flush on cable pull (Ewan D. Milne) [RHEL-39549] {CVE-2024-26931}
    - x86/bugs: Fix BHI retpoline check (Waiman Long) [RHEL-28202] {CVE-2024-2201}
    - x86/bugs: Replace CONFIG_SPECTRE_BHI_{ON,OFF} with CONFIG_MITIGATION_SPECTRE_BHI (Waiman Long)
    [RHEL-28202] {CVE-2024-2201}
    - x86/bugs: Remove CONFIG_BHI_MITIGATION_AUTO and spectre_bhi=auto (Waiman Long) [RHEL-28202]
    {CVE-2024-2201}
    - x86/bugs: Clarify that syscall hardening isn't a BHI mitigation (Waiman Long) [RHEL-28202]
    {CVE-2024-2201}
    - x86/bugs: Fix BHI handling of RRSBA (Waiman Long) [RHEL-28202] {CVE-2024-2201}
    - x86/bugs: Rename various 'ia32_cap' variables to 'x86_arch_cap_msr' (Waiman Long) [RHEL-28202]
    {CVE-2024-2201}
    - x86/bugs: Cache the value of MSR_IA32_ARCH_CAPABILITIES (Waiman Long) [RHEL-28202] {CVE-2024-2201}
    - x86/bugs: Fix BHI documentation (Waiman Long) [RHEL-28202] {CVE-2024-2201}
    - x86/bugs: Fix return type of spectre_bhi_state() (Waiman Long) [RHEL-28202] {CVE-2024-2201}
    - x86/bugs: Make CONFIG_SPECTRE_BHI_ON the default (Waiman Long) [RHEL-28202] {CVE-2024-2201}
    - x86/bhi: Mitigate KVM by default (Waiman Long) [RHEL-28202] {CVE-2024-2201}
    - x86/bhi: Add BHI mitigation knob (Waiman Long) [RHEL-28202] {CVE-2024-2201}
    - x86/bhi: Enumerate Branch History Injection (BHI) bug (Waiman Long) [RHEL-28202] {CVE-2024-2201}
    - x86/bhi: Define SPEC_CTRL_BHI_DIS_S (Waiman Long) [RHEL-28202] {CVE-2024-2201}
    - x86/bhi: Add support for clearing branch history at syscall entry (Waiman Long) [RHEL-28202]
    {CVE-2024-2201}
    - mptcp: ensure snd_nxt is properly initialized on connect (Davide Caratti) [RHEL-39865] {CVE-2024-36889}
    - powerpc/pseries: Enforce hcall result buffer validity and size (Mamatha Inamdar) [RHEL-48291]
    {CVE-2024-40974}
    - wifi: mac80211: fix potential key use-after-free (Jose Ignacio Tornos Martinez) [RHEL-28007]
    {CVE-2023-52530}
    - cppc_cpufreq: Fix possible null pointer dereference (Mark Langsdorf) [RHEL-44137] {CVE-2024-38573}
    - net/sched: act_mirred: use the backlog for mirred ingress (Davide Caratti) [RHEL-31718] {CVE-2024-26740}
    - vfio/pci: Lock external INTx masking ops (Alex Williamson) [RHEL-31922] {CVE-2024-26810}
    - net: sched: sch_multiq: fix possible OOB write in multiq_tune() (Davide Caratti) [RHEL-43464]
    {CVE-2024-36978}
    - tcp: fix tcp_init_transfer() to not reset icsk_ca_initialized (Guillaume Nault) [RHEL-37850]
    {CVE-2021-47304}
    - pstore/ram: Fix crash when setting number of cpus to an odd number (Lenny Szubowicz) [RHEL-29471]
    {CVE-2023-52619}
    - drm/vmwgfx: fix a memleak in vmw_gmrid_man_get_node (Jocelyn Falempe) [RHEL-37101] {CVE-2023-52662}
    - drm/vmwgfx: Fix the lifetime of the bo cursor memory (Jocelyn Falempe) [RHEL-36962] {CVE-2024-35810}
    - drm/vmwgfx: Create debugfs ttm_resource_manager entry only if needed (Jocelyn Falempe) [RHEL-34987]
    {CVE-2024-26940}
    - drm/vmwgfx: Unmap the surface before resetting it on a plane state (Jocelyn Falempe) [RHEL-35217]
    {CVE-2023-52648}
    - drm/vmwgfx: Fix invalid reads in fence signaled events (Jocelyn Falempe) [RHEL-40010] {CVE-2024-36960}
    - block: Fix wrong offset in bio_truncate() (Ming Lei) [RHEL-43782] {CVE-2022-48747}
    - bonding: Fix out-of-bounds read in bond_option_arp_ip_targets_set() (CKI Backport Bot) [RHEL-46913]
    {CVE-2024-39487}
    - net: fix __dst_negative_advice() race (Xin Long) [RHEL-41183] {CVE-2024-36971}
    - igc: avoid returning frame twice in XDP_REDIRECT (Corinna Vinschen) [RHEL-33264] {CVE-2024-26853}
    - mac802154: fix llsec key resources release in mac802154_llsec_key_del (Steve Best) [RHEL-34967]
    {CVE-2024-26961}
    - cpufreq: exit() callback is optional (Mark Langsdorf) [RHEL-43840] {CVE-2024-38615}
    - md/raid5: fix deadlock that raid5d() wait for itself to clear MD_SB_CHANGE_PENDING (Nigel Croxon)
    [RHEL-46662] {CVE-2024-39476}
    - net: fix information leakage in /proc/net/ptype (Hangbin Liu) [RHEL-44000] {CVE-2022-48757}
    - usb: typec: ucsi: Limit read size on v1.2 (Desnes Nunes) [RHEL-37286] {CVE-2024-35924}
    - userfaultfd: fix a race between writeprotect and exit_mmap() (Rafael Aquini) [RHEL-38410]
    {CVE-2021-47461}
    - mm: khugepaged: skip huge page collapse for special files (Waiman Long) [RHEL-38446] {CVE-2021-47491}
    - cachefiles: fix memory leak in cachefiles_add_cache() (Andrey Albershteyn) [RHEL-33109] {CVE-2024-26840}
    - drm/amd/display: Implement bounds check for stream encoder creation in DCN301 (Michel Danzer)
    [RHEL-31429] {CVE-2024-26660}
    - net/mlx5: Discard command completions in internal error (Kamal Heib) [RHEL-44231] {CVE-2024-38555}
    - drm: Don't unref the same fb many times by mistake due to deadlock handling (CKI Backport Bot)
    [RHEL-29011] {CVE-2023-52486}
    - md: fix resync softlockup when bitmap size is less than array size (Nigel Croxon) [RHEL-43942]
    {CVE-2024-38598}
    - rtnetlink: Correct nested IFLA_VF_VLAN_LIST attribute validation (Davide Caratti) [RHEL-39712]
    {CVE-2024-36017}
    - netfilter: nf_tables: discard table flag update with pending basechain deletion (Phil Sutter)
    [RHEL-37205] {CVE-2024-35897}
    - scsi: lpfc: Release hbalock before calling lpfc_worker_wake_up() (Ewan D. Milne) [RHEL-40172]
    {CVE-2024-36924}
    - scsi: lpfc: Move NPIV's transport unregistration to after resource clean up (Ewan D. Milne) [RHEL-40172]
    {CVE-2024-36952}
    - netfilter: nf_tables: fix memleak in map from abort path (Phil Sutter) [RHEL-35052] {CVE-2024-27011}
    - netfilter: nf_tables: reject new basechain after table flag update (Phil Sutter) [RHEL-37193]
    {CVE-2024-35900}
    - netfilter: nf_tables: flush pending destroy work before exit_net release (Phil Sutter) [RHEL-37197]
    {CVE-2024-35899}
    - netfilter: validate user input for expected length (Phil Sutter) [RHEL-37210] {CVE-2024-35896}
    - netfilter: tproxy: bail out if IP has been disabled on the device (Phil Sutter) [RHEL-44363]
    {CVE-2024-36270}
    - netfilter: nfnetlink_queue: acquire rcu_read_lock() in instance_destroy_rcu() (Phil Sutter) [RHEL-44532]
    {CVE-2024-36286}
    - netfilter: nf_tables: do not compare internal table flags on updates (Phil Sutter) [RHEL-35114]
    {CVE-2024-27065}
    - netfilter: nf_tables: Fix potential data-race in __nft_obj_type_get() (Phil Sutter) [RHEL-35028]
    {CVE-2024-27019}
    - netfilter: nf_tables: Fix potential data-race in __nft_expr_type_get() (Phil Sutter) [RHEL-35024]
    {CVE-2024-27020}
    - netfilter: conntrack: serialize hash resizes and cleanups (Phil Sutter) [RHEL-37703] {CVE-2021-47408}
    - netfilter: nf_tables: release mutex after nft_gc_seq_end from abort path (Phil Sutter) [RHEL-34217]
    {CVE-2024-26925}
    - ipvlan: add ipvlan_route_v6_outbound() helper (Davide Caratti) [RHEL-38319] {CVE-2023-52796}
    - net: bridge: xmit: make sure we have at least eth header len bytes (cki-backport-bot) [RHEL-44291]
    {CVE-2024-38538}
    - drivers/amd/pm: fix a use-after-free in kv_parse_power_table (Michel Danzer) [RHEL-26893]
    {CVE-2023-52469}
    - SUNRPC: Fix a suspicious RCU usage warning (Scott Mayhew) [RHEL-30503] {CVE-2023-52623}
    - ice: Fix some null pointer dereference issues in ice_ptp.c (Petr Oros) [RHEL-26901] {CVE-2023-52471}
    - sched/psi: Fix use-after-free in ep_remove_wait_queue() (Phil Auld) [RHEL-38117] {CVE-2023-52707}
    - net/ipv6: avoid possible UAF in ip6_route_mpath_notify() (Hangbin Liu) [RHEL-33269] {CVE-2024-26852}
    - net: bridge: switchdev: Skip MDB replays of deferred events on offload (Ivan Vecera) [RHEL-33117]
    {CVE-2024-26837}
    - ext4: avoid allocating blocks from corrupted group in ext4_mb_find_by_goal() (Pavel Reichl) [RHEL-31700]
    {CVE-2024-26772}
    - ext4: avoid allocating blocks from corrupted group in ext4_mb_try_best_found() (Pavel Reichl)
    [RHEL-31688] {CVE-2024-26773}
    - ext4: fix double-free of blocks due to wrong extents moved_len (Pavel Reichl) [RHEL-31612]
    {CVE-2024-26704}
    - net/smc: fix neighbour and rtable leak in smc_ib_find_route() (Tobias Huschle) [RHEL-39744]
    {CVE-2024-36945}
    - igb: Fix string truncation warnings in igb_set_fw_version (Corinna Vinschen) [RHEL-38452]
    {CVE-2024-36010}
    - bonding: stop the device in bond_setup_by_slave() (Hangbin Liu) [RHEL-38327] {CVE-2023-52784}
    - i40e: fix vf may be used uninitialized in this function warning (Kamal Heib) [RHEL-39702]
    {CVE-2024-36020}
    - powerpc/64: Fix the definition of the fixmap area (Mamatha Inamdar) [RHEL-27191] {CVE-2021-47018}
    - powerpc/mm/hash64: Add a variable to track the end of IO mapping (Mamatha Inamdar) [RHEL-27191]
    {CVE-2021-47018}
    - nsh: Restore skb->{protocol,data,mac_header} for outer header in nsh_gso_segment(). (Xin Long)
    [RHEL-39770] {CVE-2024-36933}
    - net: core: reject skb_copy(_expand) for fraglist GSO skbs (Xin Long) [RHEL-39779] {CVE-2024-36929}
    - tcp: properly terminate timers for kernel sockets (Guillaume Nault) [RHEL-37171] {CVE-2024-35910}
    - tcp: defer shutdown(SEND_SHUTDOWN) for TCP_SYN_RECV sockets (Florian Westphal) [RHEL-39831]
    {CVE-2024-36905}
    - drm/ast: Fix soft lockup (cki-backport-bot) [RHEL-37438] {CVE-2024-35952}
    - wifi: iwlwifi: mvm: guard against invalid STA ID on removal (Jose Ignacio Tornos Martinez) [RHEL-39801]
    {CVE-2024-36921}
    - ipv4: Fix uninit-value access in __ip_make_skb() (Antoine Tenart) [RHEL-39784] {CVE-2024-36927}
    - af_unix: Fix data races in unix_release_sock/unix_stream_sendmsg (Guillaume Nault) [RHEL-43961]
    {CVE-2024-38596}
    - af_unix: Fix data-races around sk->sk_shutdown. (Guillaume Nault) [RHEL-43961] {CVE-2024-38596}
    - af_unix: Fix data races around sk->sk_shutdown. (Guillaume Nault) [RHEL-43961] {CVE-2024-38596}
    - media: bttv: fix use after free error due to btv->timeout timer (Kate Hsuan) [RHEL-38256]
    {CVE-2023-52847}
    - arp: Prevent overflow in arp_req_get(). (Antoine Tenart) [RHEL-31706] {CVE-2024-26733}
    - mm: swap: fix race between free_swap_and_cache() and swapoff() (Waiman Long) [RHEL-34971]
    {CVE-2024-26960}
    - swap: comments get_swap_device() with usage rule (Waiman Long) [RHEL-34971] {CVE-2024-26960}
    - mm/swapfile.c: __swap_entry_free() always free 1 entry (Waiman Long) [RHEL-34971] {CVE-2024-26960}
    - mm/swapfile.c: call free_swap_slot() in __swap_entry_free() (Waiman Long) [RHEL-34971] {CVE-2024-26960}
    - mm/swapfile.c: use __try_to_reclaim_swap() in free_swap_and_cache() (Waiman Long) [RHEL-34971]
    {CVE-2024-26960}
    - net: amd-xgbe: Fix skb data length underflow (Ken Cox) [RHEL-43788] {CVE-2022-48743}
    - ovl: fix warning in ovl_create_real() (cki-backport-bot) [RHEL-43652] {CVE-2021-47579}
    - net/sched: Fix mirred deadlock on device recursion (Davide Caratti) [RHEL-35056] {CVE-2024-27010}
    - ext4: fix mb_cache_entry's e_refcnt leak in ext4_xattr_block_cache_find() (Pavel Reichl) [RHEL-45029]
    {CVE-2024-39276}
    - ethernet: hisilicon: hns: hns_dsaf_misc: fix a possible array overflow in hns_dsaf_ge_srst_by_port()
    (Ken Cox) [RHEL-38713] {CVE-2021-47548}
    - ipvlan: Dont Use skb->sk in ipvlan_process_v{4,6}_outbound (Hangbin Liu) [RHEL-44396] {CVE-2024-33621}
    - mlxsw: spectrum_acl_tcam: Fix stack corruption (Ivan Vecera) [RHEL-26462] {CVE-2024-26586}
    - inet: inet_defrag: prevent sk release while still in use (Antoine Tenart) [RHEL-33398] {CVE-2024-26921}
    - SUNRPC: Fix RPC client cleaned up the freed pipefs dentries (Scott Mayhew) [RHEL-38264] {CVE-2023-52803}
    - scsi: qla2xxx: Fix off by one in qla_edif_app_getstats() (Ewan D. Milne) [RHEL-39717] {CVE-2024-36025}
    - tcp: add sanity checks to rx zerocopy (Guillaume Nault) [RHEL-29494] {CVE-2024-26640}
    - SUNRPC: fix some memleaks in gssx_dec_option_array (Scott Mayhew) [RHEL-35209] {CVE-2024-27388}
    - wifi: nl80211: don't free NULL coalescing rule (Jose Ignacio Tornos Martinez) [RHEL-39752]
    {CVE-2024-36941}
    - nfs: fix UAF in direct writes (Scott Mayhew) [RHEL-34975] {CVE-2024-26958}
    - NFSv4.2: fix nfs4_listxattr kernel BUG at mm/usercopy.c:102 (Scott Mayhew) [RHEL-33228] {CVE-2024-26870}
    - block: prevent division by zero in blk_rq_stat_sum() (Ming Lei) [RHEL-37279] {CVE-2024-35925}
    - block: fix overflow in blk_ioctl_discard() (Ming Lei) [RHEL-39811] {CVE-2024-36917}
    - virtio-blk: fix implicit overflow on virtio_max_dma_size (Ming Lei) [RHEL-38131] {CVE-2023-52762}
    - nbd: null check for nla_nest_start (Ming Lei) [RHEL-35176] {CVE-2024-27025}
    - isdn: mISDN: netjet: Fix crash in nj_probe: (Ken Cox) [RHEL-38444] {CVE-2021-47284}
    - isdn: mISDN: Fix sleeping function called from invalid context (Ken Cox) [RHEL-38400] {CVE-2021-47468}
    - net/smc: avoid data corruption caused by decline (Tobias Huschle) [RHEL-38234] {CVE-2023-52775}
    - ubi: Check for too small LEB size in VTBL code (David Arcari) [RHEL-25092] {CVE-2024-25739}
    - i2c: core: Fix atomic xfer check for non-preempt config (Steve Best) [RHEL-38313] {CVE-2023-52791}
    - i2c: core: Run atomic i2c xfer when !preemptible (Steve Best) [RHEL-38313] {CVE-2023-52791}
    - firewire: ohci: mask bus reset interrupts between ISR and bottom half (Steve Best) [RHEL-39902]
    {CVE-2024-36950}
    - ipv6: init the accept_queue's spinlocks in inet6_create (Guillaume Nault) [RHEL-28899] {CVE-2024-26614}
    - tcp: make sure init the accept_queue's spinlocks once (Guillaume Nault) [RHEL-28899] {CVE-2024-26614}
    - tty: n_gsm: fix possible out-of-bounds in gsm0_receive() (Steve Best) [RHEL-39352] {CVE-2024-36016}
    - mlxsw: spectrum_acl_tcam: Fix incorrect list API usage (Ivan Vecera) [RHEL-37484] {CVE-2024-36006}
    - pwm: Fix double shift bug (Steve Best) [RHEL-38278] {CVE-2023-52756}
    - mmc: sdio: fix possible resource leaks in some error paths (Steve Best) [RHEL-38149] {CVE-2023-52730}
    - of: unittest: Fix compile in the non-dynamic case (Steve Best) [RHEL-37070] {CVE-2023-52679}
    - of: unittest: Fix of_count_phandle_with_args() expected value message (Steve Best) [RHEL-37070]
    {CVE-2023-52679}
    - of: Fix double free in of_parse_phandle_with_args_map (Steve Best) [RHEL-37070] {CVE-2023-52679}
    - pinctrl: core: delete incorrect free in pinctrl_enable() (Steve Best) [RHEL-39756] {CVE-2024-36940}
    - pinctrl: core: fix possible memory leak in pinctrl_enable() (Steve Best) [RHEL-39756] {CVE-2024-36940}
    - media: gspca: cpia1: shift-out-of-bounds in set_flicker (Desnes Nunes) [RHEL-38331] {CVE-2023-52764}
    - tipc: fix a possible memleak in tipc_buf_append (Xin Long) [RHEL-39881] {CVE-2024-36954}
    - wifi: brcmfmac: pcie: handle randbuf allocation failure (Jose Ignacio Tornos Martinez) [RHEL-44124]
    {CVE-2024-38575}
    - tcp: Use refcount_inc_not_zero() in tcp_twsk_unique(). (Guillaume Nault) [RHEL-39835] {CVE-2024-36904}
    - wifi: mac80211: don't return unset power in ieee80211_get_tx_power() (Jose Ignacio Tornos Martinez)
    [RHEL-38159] {CVE-2023-52832}
    - wifi: ath11k: fix gtk offload status event locking (Jose Ignacio Tornos Martinez) [RHEL-38155]
    {CVE-2023-52777}
    - net: ieee802154: fix null deref in parse dev addr (Steve Best) [RHEL-38012] {CVE-2021-47257}
    - mm/hugetlb: fix missing hugetlb_lock for resv uncharge (Rafael Aquini) [RHEL-37465] {CVE-2024-36000}
    - x86/xen: Add some null pointer checking to smp.c (Vitaly Kuznetsov) [RHEL-33258] {CVE-2024-26908}
    - x86/xen: Fix memory leak in xen_smp_intr_init{_pv}() (Vitaly Kuznetsov) [RHEL-33258] {CVE-2024-26908}
    - wifi: cfg80211: check A-MSDU format more carefully (Jose Ignacio Tornos Martinez) [RHEL-37343]
    {CVE-2024-35937}
    - wifi: rtw89: fix null pointer access when abort scan (Jose Ignacio Tornos Martinez) [RHEL-37355]
    {CVE-2024-35946}
    - atl1c: Work around the DMA RX overflow issue (Ken Cox) [RHEL-38287] {CVE-2023-52834}
    - wifi: ath11k: decrease MHI channel buffer length to 8KB (Jose Ignacio Tornos Martinez) [RHEL-37339]
    {CVE-2024-35938}
    - wifi: iwlwifi: mvm: rfi: fix potential response leaks (Jose Ignacio Tornos Martinez) [RHEL-37163]
    {CVE-2024-35912}
    - USB: core: Fix access violation during port device removal (Desnes Nunes) [RHEL-39853] {CVE-2024-36896}
    - scsi: lpfc: Fix possible memory leak in lpfc_rcv_padisc() (Ewan D. Milne) [RHEL-37123] {CVE-2024-35930}
    - netfilter: nf_tables: honor table dormant flag from netdev release event path (Phil Sutter) [RHEL-37450]
    {CVE-2024-36005}
    - wifi: iwlwifi: mvm: don't set the MFP flag for the GTK (Jose Ignacio Tornos Martinez) [RHEL-36898]
    {CVE-2024-27434}
    - wifi: iwlwifi: mvm: Fix key flags for IGTK on AP interface (Jose Ignacio Tornos Martinez) [RHEL-36898]
    {CVE-2024-27434}
    - misc: lis3lv02d_i2c: Fix regulators getting en-/dis-abled twice on suspend/resume (Steve Best)
    [RHEL-36932] {CVE-2024-35824}
    - x86/mce: Make sure to grab mce_sysfs_mutex in set_bank() (Steve Best) [RHEL-37262] {CVE-2024-35876}
    - net/sched: flower: Fix chain template offload (Xin Long) [RHEL-31313] {CVE-2024-26669}
    - SUNRPC: fix a memleak in gss_import_v2_context (Scott Mayhew) [RHEL-35195] {CVE-2023-52653}
    - efivarfs: force RO when remounting if SetVariable is not supported (Pavel Reichl) [RHEL-26564]
    {CVE-2023-52463}
    - dmaengine: idxd: add a write() method for applications to submit work (Jerry Snitselaar) [RHEL-35826]
    {CVE-2024-21823}
    - dmaengine: idxd: add a new security check to deal with a hardware erratum (Jerry Snitselaar)
    [RHEL-35826] {CVE-2024-21823}
    - VFIO: Add the SPR_DSA and SPR_IAX devices to the denylist (Jerry Snitselaar) [RHEL-35826]
    {CVE-2024-21823}
    - quota: Fix potential NULL pointer dereference (Pavel Reichl) [RHEL-33219] {CVE-2024-26878}
    - stmmac: Clear variable when destroying workqueue (Izabela Bakollari) [RHEL-31822] {CVE-2024-26802}
    - powerpc/pseries/memhp: Fix access beyond end of drmem array (Mamatha Inamdar) [RHEL-26495]
    {CVE-2023-52451}
    - platform/x86: wmi: Fix opening of char device (David Arcari) [RHEL-38258] {CVE-2023-52864}
    - Revert 'net/mlx5: Block entering switchdev mode with ns inconsistency' (Kamal Heib) [RHEL-36908]
    {CVE-2023-52658}
    - ext4: fix corruption during on-line resize (Carlos Maiolino) [RHEL-36974] {CVE-2024-35807}
    - ext4: avoid online resizing failures due to oversized flex bg (Carlos Maiolino) [RHEL-30507]
    {CVE-2023-52622}
    - tracing: Do no increment trace_clock_global() by one (Jerome Marchand) [RHEL-27107] {CVE-2021-46939}
    - tracing: Restructure trace_clock_global() to never block (Jerome Marchand) [RHEL-27107] {CVE-2021-46939}
    - net/sched: act_skbmod: prevent kernel-infoleak (Xin Long) [RHEL-37220] {CVE-2024-35893}
    - tipc: Change nla_policy for bearer-related names to NLA_NUL_STRING (Xin Long) [RHEL-38307]
    {CVE-2023-52845}
    - dyndbg: fix old BUG_ON in >control parser (Waiman Long) [RHEL-37111] {CVE-2024-35947}
    - efi: runtime: Fix potential overflow of soft-reserved region size (Lenny Szubowicz) [RHEL-33096]
    {CVE-2024-26843}
    - x86/fpu: Keep xfd_state in sync with MSR_IA32_XFD (Steve Best) [RHEL-36994] {CVE-2024-35801}

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2024-5101.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-38627");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:exadata_dbserver:23.1.18.0.0::ol8");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:exadata_dbserver:24.1.4.0.0::ol8");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:8::codeready_builder");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8:10:baseos_patch");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8::baseos_latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-abi-stablelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-cross-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3-perf");
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
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 8', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var machine_uptrack_level = get_one_kb_item('Host/uptrack-uname-r');
if (machine_uptrack_level)
{
  var trimmed_uptrack_level = ereg_replace(string:machine_uptrack_level, pattern:"\.(x86_64|i[3-6]86|aarch64)$", replace:'');
  var fixed_uptrack_levels = ['4.18.0-553.16.1.el8_10'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2024-5101');
    }
  }
  __rpm_report = 'Running KSplice level of ' + trimmed_uptrack_level + ' does not meet the minimum fixed level of ' + join(fixed_uptrack_levels, sep:' / ') + ' for this advisory.\n\n';
}

var kernel_major_minor = get_kb_item('Host/uname/major_minor');
if (empty_or_null(kernel_major_minor)) exit(1, 'Unable to determine kernel major-minor level.');
var expected_kernel_major_minor = '4.18';
if (kernel_major_minor != expected_kernel_major_minor)
  audit(AUDIT_OS_NOT, 'running kernel level ' + expected_kernel_major_minor + ', it is running kernel level ' + kernel_major_minor);

var pkgs = [
    {'reference':'bpftool-4.18.0-553.16.1.el8_10', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-cross-headers-4.18.0-553.16.1.el8_10', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-cross-headers-4.18.0'},
    {'reference':'kernel-headers-4.18.0-553.16.1.el8_10', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-headers-4.18.0'},
    {'reference':'kernel-tools-4.18.0-553.16.1.el8_10', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-4.18.0'},
    {'reference':'kernel-tools-libs-4.18.0-553.16.1.el8_10', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-libs-4.18.0'},
    {'reference':'kernel-tools-libs-devel-4.18.0-553.16.1.el8_10', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-libs-devel-4.18.0'},
    {'reference':'perf-4.18.0-553.16.1.el8_10', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-perf-4.18.0-553.16.1.el8_10', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bpftool-4.18.0-553.16.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-4.18.0-553.16.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-4.18.0'},
    {'reference':'kernel-abi-stablelists-4.18.0-553.16.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-abi-stablelists-4.18.0'},
    {'reference':'kernel-core-4.18.0-553.16.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-core-4.18.0'},
    {'reference':'kernel-cross-headers-4.18.0-553.16.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-cross-headers-4.18.0'},
    {'reference':'kernel-debug-4.18.0-553.16.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-4.18.0'},
    {'reference':'kernel-debug-core-4.18.0-553.16.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-core-4.18.0'},
    {'reference':'kernel-debug-devel-4.18.0-553.16.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-devel-4.18.0'},
    {'reference':'kernel-debug-modules-4.18.0-553.16.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-modules-4.18.0'},
    {'reference':'kernel-debug-modules-extra-4.18.0-553.16.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-modules-extra-4.18.0'},
    {'reference':'kernel-devel-4.18.0-553.16.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-devel-4.18.0'},
    {'reference':'kernel-headers-4.18.0-553.16.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-headers-4.18.0'},
    {'reference':'kernel-modules-4.18.0-553.16.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-modules-4.18.0'},
    {'reference':'kernel-modules-extra-4.18.0-553.16.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-modules-extra-4.18.0'},
    {'reference':'kernel-tools-4.18.0-553.16.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-4.18.0'},
    {'reference':'kernel-tools-libs-4.18.0-553.16.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-libs-4.18.0'},
    {'reference':'kernel-tools-libs-devel-4.18.0-553.16.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-libs-devel-4.18.0'},
    {'reference':'perf-4.18.0-553.16.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-perf-4.18.0-553.16.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bpftool / kernel / kernel-abi-stablelists / etc');
}
