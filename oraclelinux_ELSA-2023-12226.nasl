#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2023-12226.
##

include('compat.inc');

if (description)
{
  script_id(173830);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/01");

  script_cve_id("CVE-2022-2196");

  script_name(english:"Oracle Linux 8 / 9 : Unbreakable Enterprise kernel (ELSA-2023-12226)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 8 / 9 host has packages installed that are affected by a vulnerability as referenced in the
ELSA-2023-12226 advisory.

    [5.15.0-100.96.32]
    - crypto: Report fips module name and version for aarch64 (Saeed Mirzamohammadi)  [Orabug: 35225251]
    - uek-rpm: Enable RFC7919 config for aarch64 (Saeed Mirzamohammadi)  [Orabug: 35225251]

    [5.15.0-100.96.31]
    - uek-rpm: Update linux-firmware dependency (Somasundaram Krishnasamy)  [Orabug: 35213423]
    - block: bio-integrity: Copy flags when bio_integrity_payload is cloned (Martin K. Petersen)  [Orabug:
    35209013]
    - scsi: qla2xxx: Synchronize the IOCB count to be in order (Quinn Tran)  [Orabug: 35209013]
    - scsi: qla2xxx: Perform lockless command completion in abort path (Nilesh Javali)  [Orabug: 35209013]

    [5.15.0-100.96.30]
    - perf/x86/uncore: Don't WARN_ON_ONCE() for a broken discovery table (Kan Liang)  [Orabug: 35151818]
    - perf/x86/uncore: Add a quirk for UPI on SPR (Kan Liang)  [Orabug: 35151818]
    - perf/x86/uncore: Ignore broken units in discovery table (Kan Liang)  [Orabug: 35151818]
    - perf/x86/uncore: Fix potential NULL pointer in uncore_get_alias_name (Kan Liang)  [Orabug: 35151818]
    - perf/x86/uncore: Factor out uncore_device_to_die() (Kan Liang)  [Orabug: 35151818]
    - Revert 'perf/x86/uncore: Factor out uncore_device_to_die()' (Thomas Tai)  [Orabug: 35151818]
    - Revert 'perf/x86/uncore: Fix potential NULL pointer in uncore_get_alias_name' (Thomas Tai)  [Orabug:
    35151818]
    - Revert 'perf/x86/uncore: Ignore broken units in discovery table' (Thomas Tai)  [Orabug: 35151818]
    - Revert 'perf/x86/uncore: Add a quirk for UPI on SPR' (Thomas Tai)  [Orabug: 35151818]
    - Revert 'perf/x86/uncore: Don't WARN_ON_ONCE() for a broken discovery table' (Thomas Tai)  [Orabug:
    35151818]
    - ionic: remove unnecessary void casts (Shannon Nelson)  [Orabug: 35166570]
    - ionic: remove unnecessary indirection (Shannon Nelson)  [Orabug: 35166570]
    - ionic: missed doorbell workaround (Allen Hubbe)  [Orabug: 35166570]
    - ionic: refactor use of ionic_rx_fill() (Neel Patel)  [Orabug: 35166570]
    - ionic: enable tunnel offloads (Neel Patel)  [Orabug: 35166570]
    - ionic: new ionic device identity level and VF start control (Shannon Nelson)  [Orabug: 35166570]
    - ionic: only save the user set VF attributes (Shannon Nelson)  [Orabug: 35166570]
    - ionic: replay VF attributes after fw crash recovery (Shannon Nelson)  [Orabug: 35166570]
    - ionic: change order of devlink port register and netdev register (Jiri Pirko)  [Orabug: 35166570]
    - ionic: no transition while stopping (Shannon Nelson)  [Orabug: 35166570]
    - ionic: use vmalloc include (Shannon Nelson)  [Orabug: 35166570]
    - ionic: clean up comments and whitespace (Shannon Nelson)  [Orabug: 35166570]
    - ionic: prefer strscpy over strlcpy (Shannon Nelson)  [Orabug: 35166570]
    - ionic: Use vzalloc for large per-queue related buffers (Brett Creeley)  [Orabug: 35166570]
    - ionic: catch transition back to RUNNING with fw_generation 0 (Shannon Nelson)  [Orabug: 35166570]
    - ionic: replace set_vf data with union (Shannon Nelson)  [Orabug: 35166570]
    - ionic: stretch heartbeat detection (Shannon Nelson)  [Orabug: 35166570]
    - ionic: remove the dbid_inuse bitmap (Shannon Nelson)  [Orabug: 35166570]
    - ionic: disable napi when ionic_lif_init() fails (Brett Creeley)  [Orabug: 35166570]
    - ionic: Cleanups in the Tx hotpath code (Brett Creeley)  [Orabug: 35166570]
    - ionic: Prevent filter add/del err msgs when the device is not available (Brett Creeley)  [Orabug:
    35166570]
    - ionic: Query FW when getting VF info via ndo_get_vf_config (Brett Creeley)  [Orabug: 35166570]
    - ionic: Allow flexibility for error reporting on dev commands (Brett Creeley)  [Orabug: 35166570]
    - ionic: Correctly print AQ errors if completions aren't received (Brett Creeley)  [Orabug: 35166570]
    - ionic: fix up printing of timeout error (Shannon Nelson)  [Orabug: 35166570]
    - ionic: better handling of RESET event (Shannon Nelson)  [Orabug: 35166570]
    - ionic: add FW_STOPPING state (Shannon Nelson)  [Orabug: 35166570]
    - ionic: separate function for watchdog init (Shannon Nelson)  [Orabug: 35166570]
    - ionic: no devlink_unregister if not registered (Shannon Nelson)  [Orabug: 35166570]
    - ionic: tame the filter no space message (Shannon Nelson)  [Orabug: 35166570]
    - ionic: allow adminq requests to override default error message (Shannon Nelson)  [Orabug: 35166570]
    - ionic: handle vlan id overflow (Shannon Nelson)  [Orabug: 35166570]
    - ionic: generic filter delete (Shannon Nelson)  [Orabug: 35166570]
    - ionic: generic filter add (Shannon Nelson)  [Orabug: 35166570]
    - ionic: add generic filter search (Shannon Nelson)  [Orabug: 35166570]
    - ionic: remove mac overflow flags (Shannon Nelson)  [Orabug: 35166570]
    - ionic: move lif mac address functions (Shannon Nelson)  [Orabug: 35166570]
    - ionic: add filterlist to debugfs (Shannon Nelson)  [Orabug: 35166570]
    - ionic: add lif param to ionic_qcq_disable (Shannon Nelson)  [Orabug: 35166570]
    - ionic: have ionic_qcq_disable decide on sending to hardware (Shannon Nelson)  [Orabug: 35166570]
    - ionic: add polling to adminq wait (Shannon Nelson)  [Orabug: 35166570]
    - ionic: move lif mutex setup and delete (Shannon Nelson)  [Orabug: 35166570]
    - ionic: check for binary values in FW ver string (Shannon Nelson)  [Orabug: 35166570]
    - ionic: remove debug stats (Shannon Nelson)  [Orabug: 35166570]
    - ionic: Move devlink registration to be last devlink command (Leon Romanovsky)  [Orabug: 35166570]
    - crypto: jitter - update max health test failure in FIPS mode (Saeed Mirzamohammadi)  [Orabug: 35160891]
    - mm: use padata for copying page ranges in vma_dup() (Anthony Yznaga)  [Orabug: 35054621]
    - mm: parallelize unmap_page_range() for some large VMAs (Anthony Yznaga)  [Orabug: 35054621]
    - mm: fix VMA_BUG_ON_MM due to mmap_lock not held (Anthony Yznaga)  [Orabug: 35054621]
    - mm: avoid early cow when copying ptes for MADV_DOEXEC (Anthony Yznaga)  [Orabug: 35054621]
    - net/rds: serialize up+down-work to relax strict ordering (Gerd Rausch)  [Orabug: 35094721]
    - nvme-pci: add NVME_QUIRK_BOGUS_NID for Samsung PM1733a (Saeed Mirzamohammadi)  [Orabug: 35145945]
    - nvme-pci: add NVME_QUIRK_BOGUS_NID for Samsung PM173X (Saeed Mirzamohammadi)  [Orabug: 35146608]
    - rds: ib: Fix non-parenthetical mutex/semaphore use (Hakon Bugge)  [Orabug: 35155112]
    - Revert 'btrfs: free device in btrfs_close_devices for a single device filesystem' (Vijayendra Suman)
    [Orabug: 35161535]

    [5.15.0-100.96.29]
    - NFSD: register/unregister of nfsd-client shrinker at nfsd startup/shutdown time (Dai Ngo)  [Orabug:
    35059907]
    - NFSD: refactoring courtesy_client_reaper to a generic low memory shrinker (Dai Ngo)  [Orabug: 35059907]
    - NFSD: unregister shrinker when nfsd_init_net() fails (Tetsuo Handa)  [Orabug: 35059907]
    - NFSD: add shrinker to reap courtesy clients on low memory condition (Dai Ngo)  [Orabug: 35059907]
    - NFSD: keep track of the number of courtesy clients in the system (Dai Ngo)  [Orabug: 35059907]
    - crypto: drbg - oversampling of Jitter RNG (Saeed Mirzamohammadi)  [Orabug: 35141114]
    - crypto: tcrypt - KAT for ffdhe* algorithms (Saeed Mirzamohammadi)  [Orabug: 35141114]
    - crypto: jitter - panic on health test failure (Saeed Mirzamohammadi)  [Orabug: 35141114]
    - scsi: qla2xxx: Update version to 10.02.08.100-k (Nilesh Javali)  [Orabug: 35007285]
    - scsi: qla2xxx: Fix IOCB resource check warning (Nilesh Javali)  [Orabug: 35007285]
    - scsi: qla2xxx: Remove increment of interface err cnt (Saurav Kashyap)  [Orabug: 35007285]
    - scsi: qla2xxx: Fix erroneous link down (Quinn Tran)  [Orabug: 35007285]
    - scsi: qla2xxx: Remove unintended flag clearing (Quinn Tran)  [Orabug: 35007285]
    - scsi: qla2xxx: Fix stalled login (Quinn Tran)  [Orabug: 35007285]
    - scsi: qla2xxx: Fix exchange oversubscription for management commands (Quinn Tran)  [Orabug: 35007285]
    - scsi: qla2xxx: Fix exchange oversubscription (Quinn Tran)  [Orabug: 35007285]
    - scsi: qla2xxx: Fix DMA-API call trace on NVMe LS requests (Arun Easi)  [Orabug: 35007285]
    - scsi: qla2xxx: Fix link failure in NPIV environment (Quinn Tran)  [Orabug: 35007285]
    - scsi: qla2xxx: Check if port is online before sending ELS (Shreyas Deodhar)  [Orabug: 35007285]
    - scsi: qla2xxx: Initialize vha->unknown_atio_[list, work] for NPIV hosts (Gleb Chesnokov)  [Orabug:
    35007285]
    - scsi: qla2xxx: Remove duplicate of vha->iocb_work initialization (Gleb Chesnokov)  [Orabug: 35007285]
    - scsi: qla2xxx: Remove unused variable 'found_devs' (Colin Ian King)  [Orabug: 35007285]
    - scsi: qla2xxx: Fix serialization of DCBX TLV data request (Rafael Mendonca)  [Orabug: 35007285]
    - scsi: qla2xxx: Remove unused declarations for qla2xxx (Gaosheng Cui)  [Orabug: 35007285]
    - scsi: qla2xxx: Fix spelling mistake 'definiton' -> 'definition' (Colin Ian King)  [Orabug: 35007285]
    - scsi: qla2xxx: Drop DID_TARGET_FAILURE use (Mike Christie)  [Orabug: 35007285]
    - ACPI: processor: idle: Disable ACPI C-state probing for xen hvm guest (Joe Jin)  [Orabug: 35043629]
    - uek-rpm: x86_64 enable CONFIG_SLS (Maciej S. Szmigiero)  [Orabug: 35073535]
    - net: qede: Remove unnecessary synchronize_irq() before free_irq() (Minghao Chi)  [Orabug: 34901373]
    - uek-rpm: Disable CONFIG_USB_NET_RNDIS_WLAN (Rhythm Mahajan)  [Orabug: 35037701]
    - certs: Add FIPS selftests (David Howells)  [Orabug: 35080500]
    - certs: Move load_certificate_list() to be with the asymmetric keys code (David Howells)  [Orabug:
    35080500]
    - uek-rpm: Enable RFC7919 config (Saeed Mirzamohammadi)  [Orabug: 35080500]
    - Revert 'KVM: x86/xen: Maintain valid mapping of Xen shared_info page' (Vijayendra Suman)  [Orabug:
    34929435]
    - Revert 'KVM: x86: Fix wall clock writes in Xen shared_info not to mark page dirty' (Vijayendra Suman)
    [Orabug: 34929435]
    - Revert 'crypto: rsa - flag instantiations as FIPS compliant' (Saeed Mirzamohammadi)  [Orabug: 35054646]
    - uek-rpm/config-aarch64: Enable CONFIG_CLK_RASPBERRYPI (Vijay Kumar)  [Orabug: 35018498]
    - vfio/mlx5: Allow loading of larger images than 512 MB (Yishai Hadas)  [Orabug: 35027279]
    - vfio/mlx5: Fix UBSAN note (Yishai Hadas)  [Orabug: 35027279]
    - vfio/mlx5: error pointer dereference in error handling (Dan Carpenter)  [Orabug: 35027279]
    - vfio/mlx5: fix error code in mlx5vf_precopy_ioctl() (Dan Carpenter)  [Orabug: 35027279]
    - vfio/mlx5: Enable MIGRATION_PRE_COPY flag (Shay Drory)  [Orabug: 35027279]
    - vfio/mlx5: Fallback to STOP_COPY upon specific PRE_COPY error (Shay Drory)  [Orabug: 35027279]
    - vfio/mlx5: Introduce multiple loads (Yishai Hadas)  [Orabug: 35027279]
    - vfio/mlx5: Consider temporary end of stream as part of PRE_COPY (Yishai Hadas)  [Orabug: 35027279]
    - vfio/mlx5: Introduce vfio precopy ioctl implementation (Yishai Hadas)  [Orabug: 35027279]
    - vfio/mlx5: Introduce SW headers for migration states (Yishai Hadas)  [Orabug: 35027279]
    - vfio/mlx5: Introduce device transitions of PRE_COPY (Yishai Hadas)  [Orabug: 35027279]
    - vfio/mlx5: Refactor to use queue based data chunks (Yishai Hadas)  [Orabug: 35027279]
    - vfio/mlx5: Refactor migration file state (Yishai Hadas)  [Orabug: 35027279]
    - vfio/mlx5: Refactor MKEY usage (Yishai Hadas)  [Orabug: 35027279]
    - vfio/mlx5: Refactor PD usage (Yishai Hadas)  [Orabug: 35027279]
    - vfio/mlx5: Enforce a single SAVE command at a time (Yishai Hadas)  [Orabug: 35027279]
    - vfio: Extend the device migration protocol with PRE_COPY (Jason Gunthorpe)  [Orabug: 35027279]
    - net/mlx5: Introduce ifc bits for pre_copy (Shay Drory)  [Orabug: 35027279]
    - net/mlx5: Add the log_min_mkey_entity_size capability (Maxim Mikityanskiy)  [Orabug: 35027279]
    - vfio/iova_bitmap: refactor iova_bitmap_set() to better handle page boundaries (Joao Martins)  [Orabug:
    35027279]
    - vfio/mlx5: Fix a typo in mlx5vf_cmd_load_vhca_state() (Yishai Hadas)  [Orabug: 35027279]
    - vfio: Add an option to get migration data size (Yishai Hadas)  [Orabug: 35027279]
    - vfio/mlx5: Switch to use module_pci_driver() macro (Shang XiaoJing)  [Orabug: 35027279]
    - uek-rpm: core: Move few modules which are recently enabled to core. (Harshit Mogalapalli)  [Orabug:
    34774213]
    - tools arch x86: Sync the msr-index.h copy with the kernel sources (Arnaldo Carvalho de Melo)  [Orabug:
    34977257]
    - crypto: panic on PCT failure for dh and ecdh (Saeed Mirzamohammadi)  [Orabug: 34971139]
    - uek-rpm: mod-extra: Move modules which are recently enabled to extras (Harshit Mogalapalli)  [Orabug:
    34774213]
    - Allow the ima keyring to trust all keys in the machine keyring (Eric Snowberg)  [Orabug: 34873856]
    - Revert 'X.509: Parse Basic Constraints for CA' (Eric Snowberg)  [Orabug: 34873856]
    - Revert 'KEYS: CA link restriction' (Eric Snowberg)  [Orabug: 34873856]
    - Revert 'integrity: restrict INTEGRITY_KEYRING_MACHINE to restrict_link_by_ca' (Eric Snowberg)  [Orabug:
    34873856]
    - Revert 'integrity: change ima link restriction to trust the machine keyring' (Eric Snowberg)  [Orabug:
    34873856]
    - net/mlx5: Drain fw_reset when removing device (Shay Drory)  [Orabug: 34816080]
    - net/mlx5e: CT: Fix setting flow_source for smfs ct tuples (Paul Blakey)  [Orabug: 34816080]
    - net/mlx5e: CT: Fix support for GRE tuples (Paul Blakey)  [Orabug: 34816080]
    - net/mlx5e: Remove HW-GRO from reported features (Gal Pressman)  [Orabug: 34816080]
    - net/mlx5e: Properly block HW GRO when XDP is enabled (Maxim Mikityanskiy)  [Orabug: 34816080]
    - net/mlx5e: Properly block LRO when XDP is enabled (Maxim Mikityanskiy)  [Orabug: 34816080]
    - net/mlx5e: Block rx-gro-hw feature in switchdev mode (Aya Levin)  [Orabug: 34816080]
    - net/mlx5e: Wrap mlx5e_trap_napi_poll into rcu_read_lock (Maxim Mikityanskiy)  [Orabug: 34816080]
    - net/mlx5: DR, Ignore modify TTL on RX if device doesn't support it (Yevgeny Kliteynik)  [Orabug:
    34816080]
    - net/mlx5: Initialize flow steering during driver probe (Shay Drory)  [Orabug: 34816080]
    - mlxsw: Avoid warning during ip6gre device removal (Amit Cohen)  [Orabug: 34816080]
    - net/mlx5: Fix matching on inner TTC (Mark Bloch)  [Orabug: 34816080]
    - net/mlx5e: Avoid checking offload capability in post_parse action (Ariel Levkovich)  [Orabug: 34816080]
    - net/mlx5e: TC, fix decap fallback to uplink when int port not supported (Ariel Levkovich)  [Orabug:
    34816080]
    - net/mlx5e: TC, Fix ct_clear overwriting ct action metadata (Ariel Levkovich)  [Orabug: 34816080]
    - net/mlx5e: Fix wrong source vport matching on tunnel rule (Ariel Levkovich)  [Orabug: 34816080]
    - net: Handle l3mdev in ip_tunnel_init_flow (David Ahern)  [Orabug: 34816080]
    - net/mlx5e: Fix build warning, detected write beyond size of field (Saeed Mahameed)  [Orabug: 34816080]
    - net/mlx5e: HTB, remove unused function declaration (Saeed Mahameed)  [Orabug: 34816080]
    - net/mlx5e: Statify function mlx5_cmd_trigger_completions (Tariq Toukan)  [Orabug: 34816080]
    - net/mlx5e: Remove MLX5E_XDP_TX_DS_COUNT (Maxim Mikityanskiy)  [Orabug: 34816080]
    - net/mlx5e: Permit XDP with non-linear legacy RQ (Maxim Mikityanskiy)  [Orabug: 34816080]
    - net/mlx5e: Support multi buffer XDP_TX (Maxim Mikityanskiy)  [Orabug: 34816080]
    - net/mlx5e: Unindent the else-block in mlx5e_xmit_xdp_buff (Maxim Mikityanskiy)  [Orabug: 34816080]
    - net/mlx5e: Implement sending multi buffer XDP frames (Maxim Mikityanskiy)  [Orabug: 34816080]
    - net/mlx5e: Don't prefill WQEs in XDP SQ in the multi buffer mode (Maxim Mikityanskiy)  [Orabug:
    34816080]
    - net/mlx5e: Remove assignment of inline_hdr.sz on XDP TX (Maxim Mikityanskiy)  [Orabug: 34816080]
    - net/mlx5e: Move mlx5e_xdpi_fifo_push out of xmit_xdp_frame (Maxim Mikityanskiy)  [Orabug: 34816080]
    - net/mlx5e: Store DMA address inside struct page (Maxim Mikityanskiy)  [Orabug: 34816080]
    - net/mlx5e: Add XDP multi buffer support to the non-linear legacy RQ (Maxim Mikityanskiy)  [Orabug:
    34816080]
    - net/mlx5e: Use page-sized fragments with XDP multi buffer (Maxim Mikityanskiy)  [Orabug: 34816080]
    - net/mlx5e: Use fragments of the same size in non-linear legacy RQ with XDP (Maxim Mikityanskiy)
    [Orabug: 34816080]
    - net/mlx5e: Prepare non-linear legacy RQ for XDP multi buffer support (Maxim Mikityanskiy)  [Orabug:
    34816080]
    - net/mlx5: Remove unused fill page array API function (Tariq Toukan)  [Orabug: 34816080]
    - net/mlx5: Remove unused exported contiguous coherent buffer allocation API (Tariq Toukan)  [Orabug:
    34816080]
    - net/mlx5: CT: Remove extra rhashtable remove on tuple entries (Paul Blakey)  [Orabug: 34816080]
    - net/mlx5: DR, Remove hw_ste from mlx5dr_ste to reduce memory (Rongwei Liu)  [Orabug: 34816080]
    - net/mlx5: DR, Remove 4 members from mlx5dr_ste_htbl to reduce memory (Rongwei Liu)  [Orabug: 34816080]
    - net/mlx5: DR, Remove num_of_entries byte_size from struct mlx5_dr_icm_chunk (Rongwei Liu)  [Orabug:
    34816080]
    - net/mlx5: DR, Remove icm_addr from mlx5dr_icm_chunk to reduce memory (Rongwei Liu)  [Orabug: 34816080]
    - net/mlx5: DR, Remove mr_addr rkey from struct mlx5dr_icm_chunk (Rongwei Liu)  [Orabug: 34816080]
    - net/mlx5: DR, Adjust structure member to reduce memory hole (Rongwei Liu)  [Orabug: 34816080]
    - net/mlx5e: Drop cqe_bcnt32 from mlx5e_skb_from_cqe_mpwrq_linear (Maxim Mikityanskiy)  [Orabug: 34816080]
    - net/mlx5e: Drop the len output parameter from mlx5e_xdp_handle (Maxim Mikityanskiy)  [Orabug: 34816080]
    - net/mlx5e: RX, Test the XDP program existence out of the handler (Tariq Toukan)  [Orabug: 34816080]
    - net/mlx5e: Build SKB in place over the first fragment in non-linear legacy RQ (Maxim Mikityanskiy)
    [Orabug: 34816080]
    - net/mlx5e: Add headroom only to the first fragment in legacy RQ (Maxim Mikityanskiy)  [Orabug: 34816080]
    - net/mlx5e: Validate MTU when building non-linear legacy RQ fragments info (Maxim Mikityanskiy)  [Orabug:
    34816080]
    - net/mlx5e: MPLSoUDP encap, support action vlan pop_eth explicitly (Maor Dickman)  [Orabug: 34816080]
    - net/mlx5e: MPLSoUDP decap, use vlan push_eth instead of pedit (Maor Dickman)  [Orabug: 34816080]
    - net/sched: add vlan push_eth and pop_eth action to the hardware IR (Maor Dickman)  [Orabug: 34816080]
    - net: Add l3mdev index to flow struct and avoid oif reset for port devices (David Ahern)  [Orabug:
    34816080]
    - net/mlx5e: Fix use-after-free in mlx5e_stats_grp_sw_update_stats (Saeed Mahameed)  [Orabug: 34816080]
    - net/mlx4_en: use kzalloc (Julia Lawall)  [Orabug: 34816080]
    - net/mlx5: Parse module mapping using mlx5_ifc (Gal Pressman)  [Orabug: 34816080]
    - net/mlx5: Query the maximum MCIA register read size from firmware (Gal Pressman)  [Orabug: 34816080]
    - net/mlx5: CT: Create smfs dr matchers dynamically (Paul Blakey)  [Orabug: 34816080]
    - net/mlx5: CT: Add software steering ct flow steering provider (Paul Blakey)  [Orabug: 34816080]
    - net/mlx5: Add smfs lib to export direct steering API to CT (Paul Blakey)  [Orabug: 34816080]
    - net/mlx5: DR, Add helper to get backing dr table from a mlx5 flow table (Paul Blakey)  [Orabug:
    34816080]
    - net/mlx5: CT: Introduce a platform for multiple flow steering providers (Paul Blakey)  [Orabug:
    34816080]
    - net/mlx5: Node-aware allocation for the doorbell pgdir (Tariq Toukan)  [Orabug: 34816080]
    - net/mlx5: Node-aware allocation for UAR (Tariq Toukan)  [Orabug: 34816080]
    - net/mlx5: Node-aware allocation for the EQs (Tariq Toukan)  [Orabug: 34816080]
    - net/mlx5: Node-aware allocation for the EQ table (Tariq Toukan)  [Orabug: 34816080]
    - net/mlx5: Node-aware allocation for the IRQ table (Tariq Toukan)  [Orabug: 34816080]
    - net/mlx5: Delete useless module.h include (Leon Romanovsky)  [Orabug: 34816080]
    - net/mlx4: Delete useless moduleparam include (Leon Romanovsky)  [Orabug: 34816080]
    - net/mlx5: DR, Add support for ConnectX-7 steering (Yevgeny Kliteynik)  [Orabug: 34816080]
    - net/mlx5: DR, Refactor ste_ctx handling for STE v0/1 (Yevgeny Kliteynik)  [Orabug: 34816080]
    - net/mlx5: DR, Rename action modify fields to reflect naming in HW spec (Yevgeny Kliteynik)  [Orabug:
    34816080]
    - net/mlx5: DR, Fix handling of different actions on the same STE in STEv1 (Yevgeny Kliteynik)  [Orabug:
    34816080]
    - net/mlx5: DR, Remove unneeded comments (Yevgeny Kliteynik)  [Orabug: 34816080]
    - net/mlx5: DR, Add support for matching on Internet Header Length (IHL) (Yevgeny Kliteynik)  [Orabug:
    34816080]
    - net/mlx5: DR, Align mlx5dv_dr API vport action with FW behavior (Shun Hao)  [Orabug: 34816080]
    - net/mlx5: Add debugfs counters for page commands failures (Moshe Shemesh)  [Orabug: 34816080]
    - net/mlx5: Add pages debugfs (Moshe Shemesh)  [Orabug: 34816080]
    - net/mlx5: Move debugfs entries to separate struct (Moshe Shemesh)  [Orabug: 34816080]
    - net/mlx5: Change release_all_pages cap bit location (Moshe Shemesh)  [Orabug: 34816080]
    - net/mlx5: Remove redundant error on reclaim pages (Moshe Shemesh)  [Orabug: 34816080]
    - net/mlx5: Remove redundant error on give pages (Moshe Shemesh)  [Orabug: 34816080]
    - net/mlx5: Remove redundant notify fail on give pages (Moshe Shemesh)  [Orabug: 34816080]
    - net/mlx5: Add command failures data to debugfs (Moshe Shemesh)  [Orabug: 34816080]
    - net/mlx5e: TC, Fix use after free in mlx5e_clone_flow_attr_for_post_act() (Dan Carpenter)  [Orabug:
    34816080]
    - net/mlx5: Support GRE conntrack offload (Toshiaki Makita)  [Orabug: 34816080]
    - mlxsw: Add support for IFLA_OFFLOAD_XSTATS_L3_STATS (Petr Machata)  [Orabug: 34816080]
    - mlxsw: Extract classification of router-related events to a helper (Petr Machata)  [Orabug: 34816080]
    - mlxsw: spectrum_router: Drop mlxsw_sp arg from counter alloc/free functions (Petr Machata)  [Orabug:
    34816080]
    - mlxsw: reg: Fix packing of router interface counters (Petr Machata)  [Orabug: 34816080]
    - net: rtnetlink: Add UAPI toggle for IFLA_OFFLOAD_XSTATS_L3_STATS (Petr Machata)  [Orabug: 34816080]
    - net: rtnetlink: Add RTM_SETSTATS (Petr Machata)  [Orabug: 34816080]
    - net: rtnetlink: Add UAPI for obtaining L3 offload xstats (Petr Machata)  [Orabug: 34816080]
    - net: dev: Add hardware stats support (Petr Machata)  [Orabug: 34816080]
    - net: rtnetlink: Propagate extack to rtnl_offload_xstats_fill() (Petr Machata)  [Orabug: 34816080]
    - net: rtnetlink: RTM_GETSTATS: Allow filtering inside nests (Petr Machata)  [Orabug: 34816080]
    - net: rtnetlink: Stop assuming that IFLA_OFFLOAD_XSTATS_* are dev-backed (Petr Machata)  [Orabug:
    34816080]
    - net: rtnetlink: Namespace functions related to IFLA_OFFLOAD_XSTATS_* (Petr Machata)  [Orabug: 34816080]
    - mlx5: add support for page_pool_get_stats (Joe Damato)  [Orabug: 34816080]
    - flow_offload: reject offload for all drivers with invalid police parameters (Jianbo Liu)  [Orabug:
    34816080]
    - net: flow_offload: add tc police action parameters (Jianbo Liu)  [Orabug: 34816080]
    - net/mlx5: Add clarification on sync reset failure (Moshe Shemesh)  [Orabug: 34816080]
    - net/mlx5: Add reset_state field to MFRL register (Moshe Shemesh)  [Orabug: 34816080]
    - net/mlx5: cmdif, Refactor error handling and reporting of async commands (Saeed Mahameed)  [Orabug:
    34816080]
    - net/mlx5: Use mlx5_cmd_do() in core create_{cq,dct} (Saeed Mahameed)  [Orabug: 34816080]
    - net/mlx5: cmdif, Add new api for command execution (Saeed Mahameed)  [Orabug: 34816080]
    - net/mlx5: cmdif, cmd_check refactoring (Saeed Mahameed)  [Orabug: 34816080]
    - net/mlx5: cmdif, Return value improvements (Saeed Mahameed)  [Orabug: 34816080]
    - net/mlx5: Lag, offload active-backup drops to hardware (Mark Bloch)  [Orabug: 34816080]
    - net/mlx5: Lag, record inactive state of bond device (Mark Bloch)  [Orabug: 34816080]
    - net/mlx5: Lag, don't use magic numbers for ports (Mark Bloch)  [Orabug: 34816080]
    - net/mlx5: Lag, use local variable already defined to access E-Switch (Mark Bloch)  [Orabug: 34816080]
    - net/mlx5: E-switch, add drop rule support to ingress ACL (Mark Bloch)  [Orabug: 34816080]
    - net/mlx5: E-switch, remove special uplink ingress ACL handling (Mark Bloch)  [Orabug: 34816080]
    - net/mlx5: E-Switch, reserve and use same uplink metadata across ports (Sunil Rani)  [Orabug: 34816080]
    - net/mlx5: Add ability to insert to specific flow group (Mark Bloch)  [Orabug: 34816080]
    - mlx5: remove unused static inlines (Jakub Kicinski)  [Orabug: 34816080]
    - mlxsw: core: Add support for OSFP transceiver modules (Danielle Ratson)  [Orabug: 34816080]
    - mlxsw: Remove resource query check (Ido Schimmel)  [Orabug: 34816080]
    - mlxsw: core: Unify method of trap support validation (Vadim Pasternak)  [Orabug: 34816080]
    - mlxsw: spectrum: Remove SP{1,2,3} defines for FW minor and subminor (Jiri Pirko)  [Orabug: 34816080]
    - mlxsw: core: Remove unnecessary asserts (Vadim Pasternak)  [Orabug: 34816080]
    - mlxsw: reg: Add 'mgpir_' prefix to MGPIR fields comments (Vadim Pasternak)  [Orabug: 34816080]
    - mlxsw: core_thermal: Remove obsolete API for query resource (Vadim Pasternak)  [Orabug: 34816080]
    - mlxsw: core_thermal: Rename labels according to naming convention (Vadim Pasternak)  [Orabug: 34816080]
    - mlxsw: core_hwmon: Fix variable names for hwmon attributes (Vadim Pasternak)  [Orabug: 34816080]
    - mlxsw: core_thermal: Avoid creation of virtual hwmon objects by thermal module (Vadim Pasternak)
    [Orabug: 34816080]
    - mlxsw: spectrum_span: Ignore VLAN entries not used by the bridge in mirroring (Ido Schimmel)  [Orabug:
    34816080]
    - mlxsw: core: Prevent trap group setting if driver does not support EMAD (Vadim Pasternak)  [Orabug:
    34816080]
    - mlxsw: spectrum: remove guards against !BRIDGE_VLAN_INFO_BRENTRY (Vladimir Oltean)  [Orabug: 34816080]
    - net/mlx5e: TC, Allow sample action with CT (Roi Dayan)  [Orabug: 34816080]
    - net/mlx5e: TC, Make post_act parse CT and sample actions (Roi Dayan)  [Orabug: 34816080]
    - net/mlx5e: TC, Clean redundant counter flag from tc action parsers (Roi Dayan)  [Orabug: 34816080]
    - net/mlx5e: Use multi table support for CT and sample actions (Roi Dayan)  [Orabug: 34816080]
    - net/mlx5e: Create new flow attr for multi table actions (Roi Dayan)  [Orabug: 34816080]
    - net/mlx5e: Add post act offload/unoffload API (Roi Dayan)  [Orabug: 34816080]
    - net/mlx5e: Pass actions param to actions_match_supported() (Roi Dayan)  [Orabug: 34816080]
    - net/mlx5e: TC, Move flow hashtable to be per rep (Paul Blakey)  [Orabug: 34816080]
    - net/mlx5e: E-Switch, Add support for tx_port_ts in switchdev mode (Aya Levin)  [Orabug: 34816080]
    - net/mlx5e: E-Switch, Add PTP counters for uplink representor (Aya Levin)  [Orabug: 34816080]
    - net/mlx5e: RX, Restrict bulk size for small Striding RQs (Tariq Toukan)  [Orabug: 34816080]
    - net/mlx5e: Default to Striding RQ when not conflicting with CQE compression (Tariq Toukan)  [Orabug:
    34816080]
    - net/mlx5e: Generalize packet merge error message (Tariq Toukan)  [Orabug: 34816080]
    - net/mlx5e: Add support for using xdp->data_meta (Alex Liu)  [Orabug: 34816080]
    - net/mlx5e: Fix spelling mistake 'supoported' -> 'supported' (Colin Ian King)  [Orabug: 34816080]
    - net: rtnetlink: rtnl_stats_get(): Emit an extack for unset filter_mask (Petr Machata)  [Orabug:
    34816080]
    - net/mlx5e: Optimize the common case condition in mlx5e_select_queue (Maxim Mikityanskiy)  [Orabug:
    34816080]
    - net/mlx5e: Optimize modulo in mlx5e_select_queue (Maxim Mikityanskiy)  [Orabug: 34816080]
    - net/mlx5e: Optimize mlx5e_select_queue (Maxim Mikityanskiy)  [Orabug: 34816080]
    - net/mlx5e: Use READ_ONCE/WRITE_ONCE for DCBX trust state (Maxim Mikityanskiy)  [Orabug: 34816080]
    - net/mlx5e: Move repeating code that gets TC prio into a function (Maxim Mikityanskiy)  [Orabug:
    34816080]
    - net/mlx5e: Use select queue parameters to sync with control flow (Maxim Mikityanskiy)  [Orabug:
    34816080]
    - net/mlx5e: Move mlx5e_select_queue to en/selq.c (Maxim Mikityanskiy)  [Orabug: 34816080]
    - net/mlx5e: Introduce select queue parameters (Maxim Mikityanskiy)  [Orabug: 34816080]
    - net/mlx5e: Sync txq2sq updates with mlx5e_xmit for HTB queues (Maxim Mikityanskiy)  [Orabug: 34816080]
    - net/mlx5e: Use a barrier after updating txq2sq (Maxim Mikityanskiy)  [Orabug: 34816080]
    - net/mlx5e: Cleanup of start/stop all queues (Maxim Mikityanskiy)  [Orabug: 34816080]
    - net/mlx5e: Use FW limitation for max MPW WQEBBs (Aya Levin)  [Orabug: 34816080]
    - net/mlx5e: Read max WQEBBs on the SQ from firmware (Aya Levin)  [Orabug: 34816080]
    - net/mlx5e: Remove unused tstamp SQ field (Tariq Toukan)  [Orabug: 34816080]
    - mlxsw: Support FLOW_ACTION_MANGLE for SIP and DIP IPv6 addresses (Danielle Ratson)  [Orabug: 34816080]
    - mlxsw: Support FLOW_ACTION_MANGLE for SIP and DIP IPv4 addresses (Danielle Ratson)  [Orabug: 34816080]
    - mlxsw: core_acl_flex_actions: Add SIP_DIP_ACTION (Danielle Ratson)  [Orabug: 34816080]
    - mlxsw: spectrum_acl: Allocate default actions for internal TCAM regions (Ido Schimmel)  [Orabug:
    34816080]
    - mlxsw: spectrum: Guard against invalid local ports (Amit Cohen)  [Orabug: 34816080]
    - mlxsw: core: Consolidate trap groups to a single event group (Jiri Pirko)  [Orabug: 34816080]
    - mlxsw: core: Move functions to register/unregister array of traps to core.c (Jiri Pirko)  [Orabug:
    34816080]
    - mlxsw: core: Move basic trap group initialization from spectrum.c (Jiri Pirko)  [Orabug: 34816080]
    - mlxsw: core: Move basic_trap_groups_set() call out of EMAD init code (Jiri Pirko)  [Orabug: 34816080]
    - mlxsw: spectrum: Set basic trap groups from an array (Jiri Pirko)  [Orabug: 34816080]
    - net/mlx5: VLAN push on RX, pop on TX (Dima Chumak)  [Orabug: 34816080]
    - net/mlx5: Introduce software defined steering capabilities (Dima Chumak)  [Orabug: 34816080]
    - net/mlx5: Remove unused TIR modify bitmask enums (Tariq Toukan)  [Orabug: 34816080]
    - net/mlx5e: CT, Remove redundant flow args from tc ct calls (Roi Dayan)  [Orabug: 34816080]
    - net/mlx5e: TC, Store mapped tunnel id on flow attr (Roi Dayan)  [Orabug: 34816080]
    - net/mlx5e: Test CT and SAMPLE on flow attr (Roi Dayan)  [Orabug: 34816080]
    - net/mlx5e: Refactor eswitch attr flags to just attr flags (Roi Dayan)  [Orabug: 34816080]
    - net/mlx5e: CT, Don't set flow flag CT for ct clear flow (Roi Dayan)  [Orabug: 34816080]
    - net/mlx5e: TC, Hold sample_attr on stack instead of pointer (Roi Dayan)  [Orabug: 34816080]
    - net/mlx5e: TC, Reject rules with multiple CT actions (Roi Dayan)  [Orabug: 34816080]
    - net/mlx5e: TC, Pass attr to tc_act can_offload() (Roi Dayan)  [Orabug: 34816080]
    - net/mlx5e: TC, Split pedit offloads verify from alloc_tc_pedit_action() (Roi Dayan)  [Orabug: 34816080]
    - net/mlx5e: TC, Move pedit_headers_action to parse_attr (Roi Dayan)  [Orabug: 34816080]
    - net/mlx5e: Move counter creation call to alloc_flow_attr_counter() (Roi Dayan)  [Orabug: 34816080]
    - net/mlx5e: Pass attr arg for attaching/detaching encaps (Roi Dayan)  [Orabug: 34816080]
    - net/mlx5e: Move code chunk setting encap dests into its own function (Roi Dayan)  [Orabug: 34816080]
    - mlxsw: spectrum_kvdl: Use struct_size() helper in kzalloc() (Gustavo A. R. Silva)  [Orabug: 34816080]
    - mlxsw: core_env: Forbid module reset on RJ45 ports (Danielle Ratson)  [Orabug: 34816080]
    - mlxsw: core_env: Forbid power mode set and get on RJ45 ports (Danielle Ratson)  [Orabug: 34816080]
    - mlxsw: core_env: Forbid getting module EEPROM on RJ45 ports (Danielle Ratson)  [Orabug: 34816080]
    - mlxsw: core_env: Query and store port module's type during initialization (Danielle Ratson)  [Orabug:
    34816080]
    - mlxsw: reg: Add Port Module Type Mapping register (Danielle Ratson)  [Orabug: 34816080]
    - mlxsw: spectrum_ethtool: Add support for two new link modes (Danielle Ratson)  [Orabug: 34816080]
    - mlxsw: Add netdev argument to mlxsw_env_get_module_info() (Danielle Ratson)  [Orabug: 34816080]
    - mlxsw: core_env: Do not pass number of modules as argument (Ido Schimmel)  [Orabug: 34816080]
    - mlxsw: spectrum_ethtool: Remove redundant variable (Ido Schimmel)  [Orabug: 34816080]
    - bpf: introduce BPF_F_XDP_HAS_FRAGS flag in prog_flags loading the ebpf program (Lorenzo Bianconi)
    [Orabug: 34816080]
    - net: xdp: add xdp_update_skb_shared_info utility routine (Lorenzo Bianconi)  [Orabug: 34816080]
    - xdp: introduce flags field in xdp_buff/xdp_frame (Lorenzo Bianconi)  [Orabug: 34816080]
    - net: skbuff: add size metadata to skb_shared_info for xdp (Lorenzo Bianconi)  [Orabug: 34816080]
    - flow_offload: allow user to offload tc action to net device (Baowen Zheng)  [Orabug: 34816080]
    - flow_offload: add ops to tc_action_ops for flow action setup (Baowen Zheng)  [Orabug: 34816080]
    - flow_offload: rename offload functions with offload instead of flow (Baowen Zheng)  [Orabug: 34816080]
    - devlink: hold the instance lock during eswitch_mode callbacks (Jakub Kicinski)  [Orabug: 34816080]
    - netdevsim: replace vfs_lock with devlink instance lock (Jakub Kicinski)  [Orabug: 34816080]
    - netdevsim: fix uninit value in nsim_drv_configure_vfs() (Jakub Kicinski)  [Orabug: 34816080]
    - netdevsim: replace port_list_lock with devlink instance lock (Jakub Kicinski)  [Orabug: 34816080]
    - devlink: add explicitly locked flavor of the rate node APIs (Jakub Kicinski)  [Orabug: 34816080]
    - bnxt: use the devlink instance lock to protect sriov (Jakub Kicinski)  [Orabug: 34816080]
    - devlink: pass devlink_port to port_split / port_unsplit callbacks (Jakub Kicinski)  [Orabug: 34816080]
    - devlink: hold the instance lock in port_split / port_unsplit callbacks (Jakub Kicinski)  [Orabug:
    34816080]
    - eth: mlxsw: switch to explicit locking for port registration (Jakub Kicinski)  [Orabug: 34816080]
    - eth: nfp: replace driver's 'pf' lock with devlink instance lock (Jakub Kicinski)  [Orabug: 34816080]
    - eth: nfp: wrap locking assertions in helpers (Jakub Kicinski)  [Orabug: 34816080]
    - devlink: expose instance locking and add locked port registering (Jakub Kicinski)  [Orabug: 34816080]
    - netdevsim: rename 'driver' entry points (Jakub Kicinski)  [Orabug: 34816080]
    - netdevsim: move max vf config to dev (Jakub Kicinski)  [Orabug: 34816080]
    - netdevsim: move details of vf config to dev (Jakub Kicinski)  [Orabug: 34816080]
    - uek-rpm: Define CONFIG_MLX5_VFIO_PCI=m (Joao Martins)  [Orabug: 34778256]
    - vfio/mlx5: Set VF as migratable (Yishai Hadas)  [Orabug: 34778256]
    - net/mlx5: Introduce ifc bits for migratable (Yishai Hadas)  [Orabug: 34778256]
    - vfio/iova_bitmap: Fix PAGE_SIZE unaligned bitmaps (Joao Martins)  [Orabug: 34778256]
    - vfio/mlx5: Set the driver DMA logging callbacks (Yishai Hadas)  [Orabug: 34778256]
    - vfio/mlx5: Manage error scenarios on tracker (Yishai Hadas)  [Orabug: 34778256]
    - vfio/mlx5: Report dirty pages from tracker (Yishai Hadas)  [Orabug: 34778256]
    - vfio/mlx5: Create and destroy page tracker object (Yishai Hadas)  [Orabug: 34778256]
    - vfio/mlx5: Init QP based resources for dirty tracking (Yishai Hadas)  [Orabug: 34778256]
    - vfio: Introduce the DMA logging feature support (Yishai Hadas)  [Orabug: 34778256]
    - vfio: Add an IOVA bitmap support (Joao Martins)  [Orabug: 34778256]
    - vfio: Introduce DMA logging uAPIs (Yishai Hadas)  [Orabug: 34778256]
    - net/mlx5: Query ADV_VIRTUALIZATION capabilities (Yishai Hadas)  [Orabug: 34778256]
    - net/mlx5: Introduce ifc bits for page tracker (Yishai Hadas)  [Orabug: 34778256]
    - vfio: Move vfio.c to vfio_main.c (Jason Gunthorpe)  [Orabug: 34778256]
    - net/mlx5: Use software VHCA id when it's supported (Yishai Hadas)  [Orabug: 34778256]
    - net/mlx5: Introduce ifc bits for using software vhca id (Yishai Hadas)  [Orabug: 34778256]
    - vfio: Split migration ops from main device ops (Yishai Hadas)  [Orabug: 34778256]
    - vfio/mlx5: Protect mlx5vf_disable_fds() upon close device (Yishai Hadas)  [Orabug: 34778256]
    - vfio/pci: Have all VFIO PCI drivers store the vfio_pci_core_device in drvdata (Jason Gunthorpe)
    [Orabug: 34778256]
    - vfio/mlx5: Run the SAVE state command in an async mode (Yishai Hadas)  [Orabug: 34778256]
    - vfio/mlx5: Refactor to enable VFs migration in parallel (Yishai Hadas)  [Orabug: 34778256]
    - vfio/mlx5: Manage the VF attach/detach callback from the PF (Yishai Hadas)  [Orabug: 34778256]
    - net/mlx5: Expose mlx5_sriov_blocking_notifier_register / unregister APIs (Yishai Hadas)  [Orabug:
    34778256]
    - vfio/mlx5: Fix to not use 0 as NULL pointer (Yishai Hadas)  [Orabug: 34778256]
    - vfio/mlx5: Use its own PCI reset_done error handler (Yishai Hadas)  [Orabug: 34778256]
    - vfio/pci: Expose vfio_pci_core_aer_err_detected() (Yishai Hadas)  [Orabug: 34778256]
    - vfio/mlx5: Implement vfio_pci driver for mlx5 devices (Yishai Hadas)  [Orabug: 34778256]
    - vfio/mlx5: Expose migration commands over mlx5 device (Yishai Hadas)  [Orabug: 34778256]
    - vfio: Remove migration protocol v1 documentation (Jason Gunthorpe)  [Orabug: 34778256]
    - vfio: Extend the device migration protocol with RUNNING_P2P (Jason Gunthorpe)  [Orabug: 34778256]
    - vfio: Define device migration protocol v2 (Jason Gunthorpe)  [Orabug: 34778256]
    - vfio: Have the core code decode the VFIO_DEVICE_FEATURE ioctl (Jason Gunthorpe)  [Orabug: 34778256]
    - net/mlx5: Add migration commands definitions (Yishai Hadas)  [Orabug: 34778256]
    - net/mlx5: Introduce migration bits and structures (Yishai Hadas)  [Orabug: 34778256]
    - net/mlx5: Expose APIs to get/put the mlx5 core device (Yishai Hadas)  [Orabug: 34778256]
    - PCI/IOV: Add pci_iov_get_pf_drvdata() to allow VF reaching the drvdata of a PF (Jason Gunthorpe)
    [Orabug: 34778256]
    - net/mlx5: Disable SRIOV before PF removal (Yishai Hadas)  [Orabug: 34778256]
    - net/mlx5: Reuse exported virtfn index function call (Leon Romanovsky)  [Orabug: 34778256]
    - PCI/IOV: Add pci_iov_vf_id() to get VF index (Jason Gunthorpe)  [Orabug: 34778256]
    - NFSv4.2: Fix up an invalid combination of memory allocation flags (Trond Myklebust)  [Orabug: 34844640]
    - Add SecureBoot signing for aarch64 arch (Sherry Yang)  [Orabug: 34845745]
    - uek-rpm: Fix 'make olddefconfig' BLAKE2S crypto warnings (Harshit Mogalapalli)  [Orabug: 34644522]
    - RHCK 9.1 builtin option change to module for UEK7u1 (Vijayendra Suman)  [Orabug: 34687867]
    - uek-rpm: Disable few config options that we enabled previously. (Harshit Mogalapalli)  [Orabug:
    34803318]
    - qlogic: qed: fix clang -Wformat warnings (Justin Stitt)  [Orabug: 34789504]
    - qed: Use bitmap_empty() (Christophe JAILLET)  [Orabug: 34789504]
    - qed: Use the bitmap API to allocate bitmaps (Christophe JAILLET)  [Orabug: 34789504]
    - qlogic/qed: fix repeated words in comments (Jilin Yuan)  [Orabug: 34789504]
    - qed: fix typos in comments (Julia Lawall)  [Orabug: 34789504]
    - net: qed: fix typos in comments (Julia Lawall)  [Orabug: 34789504]
    - RDMA/qedr: Remove unnecessary synchronize_irq() before free_irq() (Minghao Chi)  [Orabug: 34789504]
    - qed: Remove unnecessary synchronize_irq() before free_irq() (Minghao Chi)  [Orabug: 34789504]
    - qed: replace bitmap_weight with bitmap_empty in qed_roce_stop() (Yury Norov)  [Orabug: 34789504]
    - qed: rework qed_rdma_bmap_free() (Yury Norov)  [Orabug: 34789504]
    - qede: Reduce verbosity of ptp tx timestamp (Prabhakar Kushwaha)  [Orabug: 34789504]
    - qed: Remove IP services API. (Guillaume Nault)  [Orabug: 34789504]
    - qed: remove an unneed NULL check on list iterator (Xiaomeng Tong)  [Orabug: 34789504]
    - qed: fix ethtool register dump (Manish Chopra)  [Orabug: 34789504]
    - qed: remove unnecessary memset in qed_init_fw_funcs (Wan Jiabing)  [Orabug: 34789504]
    - qed: prevent a fw assert during device shutdown (Venkata Sudheer Kumar Bhavaraju)  [Orabug: 34789504]
    - qed: use msleep() in qed_mcp_cmd() and add qed_mcp_cmd_nosleep() for udelay. (Venkata Sudheer Kumar
    Bhavaraju)  [Orabug: 34789504]
    - qed: Use dma_set_mask_and_coherent() and simplify code (Christophe JAILLET)  [Orabug: 34789504]
    - qed*: esl priv flag support through ethtool (Manish Chopra)  [Orabug: 34789504]
    - qed*: enhance tx timeout debug info (Manish Chopra)  [Orabug: 34789504]
    - qed: Enhance rammod debug prints to provide pretty details (Prabhakar Kushwaha)  [Orabug: 34789504]
    - net: qed: fix the array may be out of bound (zhangyue)  [Orabug: 34789504]
    - qed: Use the bitmap API to simplify some functions (Christophe JAILLET)  [Orabug: 34789504]
    - RDMA/qed: Use helper function to set GUIDs (Kamal Heib)  [Orabug: 34789504]
    - net: qed_dev: fix check of true !rc expression (Jean Sacren)  [Orabug: 34789504]
    - net: qed_ptp: fix check of true !rc expression (Jean Sacren)  [Orabug: 34789504]
    - RDMA/qedr: Remove unsupported qedr_resize_cq callback (Kamal Heib)  [Orabug: 34789504]
    - qed: Change the TCP common variable - 'iscsi_ooo' (Shai Malin)  [Orabug: 34789504]
    - qed: Optimize the ll2 ooo flow (Shai Malin)  [Orabug: 34789504]
    - net: qed_debug: fix check of false (grc_param < 0) expression (Jean Sacren)  [Orabug: 34789504]
    - qed: Fix compilation for CONFIG_QED_SRIOV undefined scenario (Prabhakar Kushwaha)  [Orabug: 34789504]
    - qed: Initialize debug string array (Tim Gardner)  [Orabug: 34789504]
    - qed: Fix spelling mistake 'ctx_bsaed' -> 'ctx_based' (Colin Ian King)  [Orabug: 34789504]
    - qed: fix ll2 establishment during load of RDMA driver (Manish Chopra)  [Orabug: 34789504]
    - qed: Update the TCP active termination 2 MSL timer ('TIME_WAIT') (Prabhakar Kushwaha)  [Orabug:
    34789504]
    - qed: Update TCP silly-window-syndrome timeout for iwarp, scsi (Nikolay Assa)  [Orabug: 34789504]
    - qed: Update debug related changes (Prabhakar Kushwaha)  [Orabug: 34789504]
    - qed: Add '_GTT' suffix to the IRO RAM macros (Prabhakar Kushwaha)  [Orabug: 34789504]
    - qed: Update FW init functions to support FW 8.59.1.0 (Omkar Kulkarni)  [Orabug: 34789504]
    - qed: Use enum as per FW 8.59.1.0 in qed_iro_hsi.h (Prabhakar Kushwaha)  [Orabug: 34789504]
    - qed: Update qed_hsi.h for fw 8.59.1.0 (Prabhakar Kushwaha)  [Orabug: 34789504]
    - qed: Update qed_mfw_hsi.h for FW ver 8.59.1.0 (Prabhakar Kushwaha)  [Orabug: 34789504]
    - qed: Update common_hsi for FW ver 8.59.1.0 (Prabhakar Kushwaha)  [Orabug: 34789504]
    - qed: Split huge qed_hsi.h header file (Omkar Kulkarni)  [Orabug: 34789504]
    - qed: Remove e4_ and _e4 from FW HSI (Shai Malin)  [Orabug: 34789504]
    - pmem: fix a name collision (Jane Chu)  [Orabug: 34670103]
    - pmem: implement pmem_recovery_write() (Jane Chu)  [Orabug: 34670103]
    - pmem: refactor pmem_clear_poison() (Jane Chu)  [Orabug: 34670103]
    - dax: add .recovery_write dax_operation (Jane Chu)  [Orabug: 34670103]
    - dax: introduce DAX_RECOVERY_WRITE dax access mode (Jane Chu)  [Orabug: 34670103]
    - dm-linear: add a linear_dax_pgoff helpe (Jane Chu)  [Orabug: 34670103]
    - dm-log-writes: add a log_writes_dax_pgoff helper (Jane Chu)  [Orabug: 34670103]
    - dm-stripe: add a stripe_dax_pgoff helper (Jane Chu)  [Orabug: 34670103]
    - mce: fix set_mce_nospec to always unmap the whole page (Jane Chu)  [Orabug: 34670103]
    - x86/mce: relocate set{clear}_mce_nospec() functions (Jane Chu)  [Orabug: 34670103]
    - acpi/nfit: rely on mce->misc to determine poison granularity (Jane Chu)  [Orabug: 34670103]
    - crypto: seqiv - flag instantiations as FIPS compliant (Vladis Dronov)  [Orabug: 34711430]
    - crypto: rsa - flag instantiations as FIPS compliant (Saeed Mirzamohammadi)  [Orabug: 34711430]
    - crypto: ecdh - implement FIPS PCT (Nicolai Stange)  [Orabug: 34711430]
    - crypto: dh - implement FIPS PCT (Nicolai Stange)  [Orabug: 34711430]
    - crypto: dh - calculate Q from P for the full public key verification (Nicolai Stange)  [Orabug:
    34711430]
    - lib/mpi: export mpi_rshift (Nicolai Stange)  [Orabug: 34711430]
    - crypto: dh - allow for passing NULL to the ffdheXYZ(dh)s' ->set_secret() (Nicolai Stange)  [Orabug:
    34711430]
    - crypto: testmgr - add keygen tests for ffdheXYZ(dh) templates (Nicolai Stange)  [Orabug: 34711430]
    - crypto: dh - implement private key generation primitive for ffdheXYZ(dh) (Nicolai Stange)  [Orabug:
    34711430]
    - crypto: testmgr - add known answer tests for ffdheXYZ(dh) templates (Nicolai Stange)  [Orabug: 34711430]
    - crypto: dh - implement ffdheXYZ(dh) templates (Nicolai Stange)  [Orabug: 34711430]
    - crypto: dh - introduce common code for built-in safe-prime group support (Nicolai Stange)  [Orabug:
    34711430]
    - crypto: dh - split out deserialization code from crypto_dh_decode() (Nicolai Stange)  [Orabug: 34711430]
    - crypto: dh - constify struct dh's pointer members (Nicolai Stange)  [Orabug: 34711430]
    - crypto: dh - remove struct dh's ->q member (Nicolai Stange)  [Orabug: 34711430]
    - crypto: kpp - provide support for KPP spawns (Nicolai Stange)  [Orabug: 34711430]
    - crypto: kpp - provide support for KPP template instances (Nicolai Stange)  [Orabug: 34711430]
    - crypto: xts - restrict key lengths to approved values in FIPS mode (Nicolai Stange)  [Orabug: 34711430]
    - crypto: hmac - disallow keys < 112 bits in FIPS mode (Stephan Muller)  [Orabug: 34711430]
    - crypto: dh - limit key size to 2048 in FIPS mode (Stephan Muller)  [Orabug: 34711430]
    - crypto: rsa - limit key size to 2048 in FIPS mode (Stephan Muller)  [Orabug: 34711430]
    - crypto: HMAC - add fips_skip support (Stephan Muller)  [Orabug: 34711430]
    - crypto: disallow drbg with sha384 hash in FIPS mode (Saeed Mirzamohammadi)  [Orabug: 34711430]
    - crypto: des - disallow des3 in FIPS mode (Stephan Muller)  [Orabug: 34711430]
    - crypto: dh - disallow plain 'dh' usage in FIPS mode (Nicolai Stange)  [Orabug: 34711430]
    - crypto: ecdh - disallow plain 'ecdh' usage in FIPS mode (Saeed Mirzamohammadi)  [Orabug: 34711430]
    - crypto: testmgr - disallow plain cbcmac(aes) and ghash in FIPS mode (Saeed Mirzamohammadi)  [Orabug:
    34711430]
    - crypto: api - allow algs only in specific constructions in FIPS mode (Nicolai Stange)  [Orabug:
    34711430]
    - NFSv4.2: Fix missing removal of SLAB_ACCOUNT on kmem_cache allocation (Muchun Song)  [Orabug: 34717841]
    - slab: remove __alloc_size attribute from __kmalloc_track_caller (Greg Kroah-Hartman)  [Orabug: 34717841]
    - mm: memcontrol: rename memcg_cache_id to memcg_kmem_id (Muchun Song)  [Orabug: 34717841]
    - mm: list_lru: rename list_lru_per_memcg to list_lru_memcg (Muchun Song)  [Orabug: 34717841]
    - mm: memcontrol: fix cannot alloc the maximum memcg ID (Muchun Song)  [Orabug: 34717841]
    - mm: memcontrol: reuse memory cgroup ID for kmem ID (Muchun Song)  [Orabug: 34717841]
    - mm: list_lru: replace linear array with xarray (Muchun Song)  [Orabug: 34717841]
    - mm: list_lru: rename memcg_drain_all_list_lrus to memcg_reparent_list_lrus (Muchun Song)  [Orabug:
    34717841]
    - mm: list_lru: allocate list_lru_one only when needed (Muchun Song)  [Orabug: 34717841]
    - mm: memcontrol: move memcg_online_kmem() to mem_cgroup_css_online() (Muchun Song)  [Orabug: 34717841]
    - xarray: use kmem_cache_alloc_lru to allocate xa_node (Muchun Song)  [Orabug: 34717841]
    - mm: dcache: use kmem_cache_alloc_lru() to allocate dentry (Muchun Song)  [Orabug: 34717841]
    - f2fs: allocate inode by using alloc_inode_sb() (Muchun Song)  [Orabug: 34717841]
    - fs: allocate inode by using alloc_inode_sb() (Muchun Song)  [Orabug: 34717841]
    - fs: introduce alloc_inode_sb() to allocate filesystems specific inode (Muchun Song)  [Orabug: 34717841]
    - mm: introduce kmem_cache_alloc_lru (Muchun Song)  [Orabug: 34717841]
    - mm: list_lru: transpose the array of per-node per-memcg lru lists (Muchun Song)  [Orabug: 34717841]
    - mm: list_lru: only add memcg-aware lrus to the global lru list (Muchun Song)  [Orabug: 34717841]
    - mm: list_lru: fix the return value of list_lru_count_one() (Muchun Song)  [Orabug: 34717841]
    - mm: list_lru: remove holding lru lock (Muchun Song)  [Orabug: 34717841]
    - mm: memcontrol: remove the kmem states (Muchun Song)  [Orabug: 34717841]
    - mm: memcontrol: remove kmemcg_id reparenting (Muchun Song)  [Orabug: 34717841]
    - mm/memcg: remove obsolete memcg_free_kmem() (Waiman Long)  [Orabug: 34717841]
    - memcg, kmem: further deprecate kmem.limit_in_bytes (Shakeel Butt)  [Orabug: 34717841]
    - mm/list_lru.c: prefer struct_size over open coded arithmetic (Len Baker)  [Orabug: 34717841]
    - slab: add __alloc_size attributes for better bounds checking (Kees Cook)  [Orabug: 34717841]
    - slab: clean up function prototypes (Kees Cook)  [Orabug: 34717841]
    - net/mlx5e: SHAMPO, reduce TIR indication (Ben Ben-Ishay)  [Orabug: 34481188]
    - net/mlx5: Fix offloading with ESWITCH_IPV4_TTL_MODIFY_ENABLE (Dima Chumak)  [Orabug: 34481188]
    - net/mlx5e: Fix VF min/max rate parameters interchange mistake (Gal Pressman)  [Orabug: 34481188]
    - net/mlx5e: Add missing increment of count (Lama Kayal)  [Orabug: 34481188]
    - net/mlx5e: Fix MPLSoUDP encap to use MPLS action information (Maor Dickman)  [Orabug: 34481188]
    - net/mlx5e: Add feature check for set fec counters (Lama Kayal)  [Orabug: 34481188]
    - net/mlx5e: TC, Skip redundant ct clear actions (Roi Dayan)  [Orabug: 34481188]
    - net/mlx5: DR, Fix slab-out-of-bounds in mlx5_cmd_dr_create_fte (Yevgeny Kliteynik)  [Orabug: 34481188]
    - net/mlx5e: Avoid field-overflowing memcpy() (Kees Cook)  [Orabug: 34481188]
    - net/mlx5e: Use struct_group() for memcpy() region (Kees Cook)  [Orabug: 34481188]
    - net/mlx5e: Avoid implicit modify hdr for decap drop rule (Roi Dayan)  [Orabug: 34481188]
    - net/mlx5e: Fix broken SKB allocation in HW-GRO (Khalid Manaa)  [Orabug: 34481188]
    - net/mlx5e: Fix wrong calculation of header index in HW_GRO (Khalid Manaa)  [Orabug: 34481188]
    - net/mlx5e: TC, Reject rules with forward and drop actions (Roi Dayan)  [Orabug: 34481188]
    - net/mlx5e: TC, Reject rules with drop and modify hdr action (Roi Dayan)  [Orabug: 34481188]
    - net/mlx5e: Fix build error in fec_set_block_stats() (Jakub Kicinski)  [Orabug: 34481188]
    - mlxsw: spectrum: Extend to support Spectrum-4 ASIC (Amit Cohen)  [Orabug: 34481188]
    - mlxsw: spectrum_acl_bloom_filter: Add support for Spectrum-4 calculation (Amit Cohen)  [Orabug:
    34481188]
    - mlxsw: Add operations structure for bloom filter calculation (Amit Cohen)  [Orabug: 34481188]
    - mlxsw: spectrum_acl_bloom_filter: Rename Spectrum-2 specific objects for future use (Amit Cohen)
    [Orabug: 34481188]
    - mlxsw: spectrum_acl_bloom_filter: Make mlxsw_sp_acl_bf_key_encode() more flexible (Amit Cohen)  [Orabug:
    34481188]
    - mlxsw: spectrum_acl_bloom_filter: Reorder functions to make the code more aesthetic (Amit Cohen)
    [Orabug: 34481188]
    - mlxsw: Introduce flex key elements for Spectrum-4 (Amit Cohen)  [Orabug: 34481188]
    - mlxsw: Rename virtual router flex key element (Amit Cohen)  [Orabug: 34481188]
    - net/mlx5e: Fix nullptr on deleting mirroring rule (Dima Chumak)  [Orabug: 34481188]
    - net/mlx5e: Add recovery flow in case of error CQE (Gal Pressman)  [Orabug: 34481188]
    - net/mlx5e: TC, Remove redundant error logging (Roi Dayan)  [Orabug: 34481188]
    - net/mlx5e: Refactor set_pflag_cqe_based_moder (Saeed Mahameed)  [Orabug: 34481188]
    - net/mlx5e: Move HW-GRO and CQE compression check to fix features flow (Gal Pressman)  [Orabug: 34481188]
    - net/mlx5e: Fix feature check per profile (Aya Levin)  [Orabug: 34481188]
    - net/mlx5e: Expose FEC counters via ethtool (Lama Kayal)  [Orabug: 34481188]
    - net/mlx5: SF, Use all available cpu for setting cpu affinity (Shay Drory)  [Orabug: 34481188]
    - net/mlx5: Introduce API for bulk request and release of IRQs (Shay Drory)  [Orabug: 34481188]
    - net/mlx5: Split irq_pool_affinity logic to new file (Shay Drory)  [Orabug: 34481188]
    - net/mlx5: Move affinity assignment into irq_request (Shay Drory)  [Orabug: 34481188]
    - net/mlx5: Introduce control IRQ request API (Shay Drory)  [Orabug: 34481188]
    - net/mlx5: mlx5e_hv_vhca_stats_create return type to void (Saeed Mahameed)  [Orabug: 34481188]
    - net: fixup build after bpf header changes (Jakub Kicinski)  [Orabug: 34481188]
    - net/mlx5: CT: Set flow source hint from provided tuple device (Paul Blakey)  [Orabug: 34481188]
    - net/mlx5: Set SMFS as a default steering mode if device supports it (Yevgeny Kliteynik)  [Orabug:
    34481188]
    - net/mlx5: DR, Ignore modify TTL if device doesn't support it (Yevgeny Kliteynik)  [Orabug: 34481188]
    - net/mlx5: DR, Improve steering for empty or RX/TX-only matchers (Yevgeny Kliteynik)  [Orabug: 34481188]
    - net/mlx5: DR, Add support for matching on geneve_tlv_option_0_exist field (Yevgeny Kliteynik)  [Orabug:
    34481188]
    - net/mlx5: DR, Support matching on tunnel headers 0 and 1 (Muhammad Sammar)  [Orabug: 34481188]
    - net/mlx5: DR, Add misc5 to match_param structs (Muhammad Sammar)  [Orabug: 34481188]
    - net/mlx5: Add misc5 flow table match parameters (Muhammad Sammar)  [Orabug: 34481188]
    - net/mlx5: DR, Warn on failure to destroy objects due to refcount (Yevgeny Kliteynik)  [Orabug: 34481188]
    - net/mlx5: DR, Add support for UPLINK destination type (Yevgeny Kliteynik)  [Orabug: 34481188]
    - net/mlx5: DR, Add support for dumping steering info (Muhammad Sammar)  [Orabug: 34481188]
    - net/mlx5: DR, Add missing reserved fields to dr_match_param (Muhammad Sammar)  [Orabug: 34481188]
    - net/mlx5: DR, Add check for flex parser ID value (Yevgeny Kliteynik)  [Orabug: 34481188]
    - net/mlx5: DR, Remove unused struct member in matcher (Yevgeny Kliteynik)  [Orabug: 34481188]
    - net/mlx5: DR, Fix lower case macro prefix 'mlx5_' to 'MLX5_' (Yevgeny Kliteynik)  [Orabug: 34481188]
    - net/mlx5: DR, Fix error flow in creating matcher (Yevgeny Kliteynik)  [Orabug: 34481188]
    - mlxsw: spectrum_flower: Make vlan_id limitation more specific (Amit Cohen)  [Orabug: 34481188]
    - net/mlx5e: Use auxiliary_device driver data helpers (David E. Box)  [Orabug: 34481188]
    - driver core: auxiliary bus: Add driver data helpers (David E. Box)  [Orabug: 34481188]
    - net/mlx5e: Take packet_merge params directly from the RX res struct (Tariq Toukan)  [Orabug: 34481188]
    - net/mlx5e: Allocate per-channel stats dynamically at first usage (Lama Kayal)  [Orabug: 34481188]
    - net/mlx5e: Use dynamic per-channel allocations in stats (Tariq Toukan)  [Orabug: 34481188]
    - net/mlx5e: Allow profile-specific limitation on max num of channels (Tariq Toukan)  [Orabug: 34481188]
    - net/mlx5e: Save memory by using dynamic allocation in netdev priv (Tariq Toukan)  [Orabug: 34481188]
    - net/mlx5e: Add profile indications for PTP and QOS HTB features (Tariq Toukan)  [Orabug: 34481188]
    - net/mlx5e: Use bitmap field for profile features (Tariq Toukan)  [Orabug: 34481188]
    - net/mlx5: Remove the repeated declaration (Shaokun Zhang)  [Orabug: 34481188]
    - net/mlx5: Let user configure max_macs generic param (Shay Drory)  [Orabug: 34481188]
    - net/mlx5: Let user configure event_eq_size param (Shay Drory)  [Orabug: 34481188]
    - devlink: Add new 'event_eq_size' generic device param (Shay Drory)  [Orabug: 34481188]
    - net/mlx5: Let user configure io_eq_size param (Shay Drory)  [Orabug: 34481188]
    - devlink: Add new 'io_eq_size' generic device param (Shay Drory)  [Orabug: 34481188]
    - mlxsw: core: Extend devlink health reporter with new events and parameters (Danielle Ratson)  [Orabug:
    34481188]
    - mlxsw: reg: Extend MFDE register with new events and parameters (Danielle Ratson)  [Orabug: 34481188]
    - mlxsw: core: Convert a series of if statements to switch case (Danielle Ratson)  [Orabug: 34481188]
    - mlxsw: Fix naming convention of MFDE fields (Danielle Ratson)  [Orabug: 34481188]
    - flow_offload: add index to flow_action_entry structure (Baowen Zheng)  [Orabug: 34481188]
    - flow_offload: reject to offload tc actions in offload drivers (Baowen Zheng)  [Orabug: 34481188]
    - net/mlx5: Introduce log_max_current_uc_list_wr_supported bit (Shay Drory)  [Orabug: 34481188]
    - mlxsw: Add support for VxLAN with IPv6 underlay (Amit Cohen)  [Orabug: 34481188]
    - mlxsw: spectrum_nve: Keep track of IPv6 addresses used by FDB entries (Amit Cohen)  [Orabug: 34481188]
    - mlxsw: reg: Add a function to fill IPv6 unicast FDB entries (Amit Cohen)  [Orabug: 34481188]
    - mlxsw: Split handling of FDB tunnel entries between address families (Amit Cohen)  [Orabug: 34481188]
    - mlxsw: spectrum_nve_vxlan: Make VxLAN flags check per address family (Amit Cohen)  [Orabug: 34481188]
    - mlxsw: spectrum_ipip: Use common hash table for IPv6 address mapping (Amit Cohen)  [Orabug: 34481188]
    - mlxsw: spectrum: Add hash table for IPv6 address mapping (Amit Cohen)  [Orabug: 34481188]
    - net/mlx5e: Move goto action checks into tc_action goto post parse op (Roi Dayan)  [Orabug: 34481188]
    - net/mlx5e: Move vlan action chunk into tc action vlan post parse op (Roi Dayan)  [Orabug: 34481188]
    - net/mlx5e: Add post_parse() op to tc action infrastructure (Roi Dayan)  [Orabug: 34481188]
    - net/mlx5e: Move sample attr allocation to tc_action sample parse op (Roi Dayan)  [Orabug: 34481188]
    - net/mlx5e: TC action parsing loop (Roi Dayan)  [Orabug: 34481188]
    - net/mlx5e: Add redirect ingress to tc action infra (Roi Dayan)  [Orabug: 34481188]
    - net/mlx5e: Add sample and ptype to tc_action infra (Roi Dayan)  [Orabug: 34481188]
    - net/mlx5e: Add ct to tc action infra (Roi Dayan)  [Orabug: 34481188]
    - net/mlx5e: Add mirred/redirect to tc action infra (Roi Dayan)  [Orabug: 34481188]
    - net/mlx5e: Add mpls push/pop to tc action infra (Roi Dayan)  [Orabug: 34481188]
    - net/mlx5e: Add vlan push/pop/mangle to tc action infra (Roi Dayan)  [Orabug: 34481188]
    - net/mlx5e: Add pedit to tc action infra (Roi Dayan)  [Orabug: 34481188]
    - net/mlx5e: Add csum to tc action infra (Roi Dayan)  [Orabug: 34481188]
    - net/mlx5e: Add tunnel encap/decap to tc action infra (Roi Dayan)  [Orabug: 34481188]
    - net/mlx5e: Add goto to tc action infra (Roi Dayan)  [Orabug: 34481188]
    - net/mlx5e: Add tc action infrastructure (Roi Dayan)  [Orabug: 34481188]
    - net_tstamp: add new flag HWTSTAMP_FLAG_BONDED_PHC_INDEX (Hangbin Liu)  [Orabug: 34481188]
    - net/mlx5: Create more priorities for FDB bypass namespace (Maor Gottlieb)  [Orabug: 34481188]
    - net/mlx5: Refactor mlx5_get_flow_namespace (Maor Gottlieb)  [Orabug: 34481188]
    - net/mlx5: Separate FDB namespace (Maor Gottlieb)  [Orabug: 34481188]
    - bpf: Let bpf_warn_invalid_xdp_action() report more info (Paolo Abeni)  [Orabug: 34481188]
    - net/mlx4: Use irq_update_affinity_hint() (Nitesh Narayan Lal)  [Orabug: 34481188]
    - net/mlx5: Use irq_set_affinity_and_hint() (Nitesh Narayan Lal)  [Orabug: 34481188]
    - genirq: Provide new interfaces for affinity hints (Thomas Gleixner)  [Orabug: 34481188]
    - net/mlx5: Dynamically resize flow counters query buffer (Avihai Horon)  [Orabug: 34481188]
    - net/mlx5e: TC, Set flow attr ip_version earlier (Roi Dayan)  [Orabug: 34481188]
    - net/mlx5e: TC, Move common flow_action checks into function (Roi Dayan)  [Orabug: 34481188]
    - net/mlx5e: Remove redundant actions arg from vlan push/pop funcs (Roi Dayan)  [Orabug: 34481188]
    - net/mlx5e: Remove redundant actions arg from validate_goto_chain() (Roi Dayan)  [Orabug: 34481188]
    - net/mlx5e: TC, Remove redundant action stack var (Roi Dayan)  [Orabug: 34481188]
    - net/mlx5e: Hide function mlx5e_num_channels_changed (Tariq Toukan)  [Orabug: 34481188]
    - net/mlx5e: SHAMPO, clean MLX5E_MAX_KLM_PER_WQE macro (Ben Ben-Ishay)  [Orabug: 34481188]
    - net/mlx5: SF, silence an uninitialized variable warning (Dan Carpenter)  [Orabug: 34481188]
    - net/mlx5: Fix error return code in esw_qos_create() (Wei Yongjun)  [Orabug: 34481188]
    - mlx5: fix mlx5i_grp_sw_update_stats() stack usage (Arnd Bergmann)  [Orabug: 34481188]
    - mlx5: fix psample_sample_packet link error (Arnd Bergmann)  [Orabug: 34481188]
    - mlxsw: Use Switch Multicast ID Register Version 2 (Amit Cohen)  [Orabug: 34481188]
    - mlxsw: Use Switch Flooding Table Register Version 2 (Amit Cohen)  [Orabug: 34481188]
    - mlxsw: Add support for more than 256 ports in SBSR register (Amit Cohen)  [Orabug: 34481188]
    - mlxsw: Use u16 for local_port field instead of u8 (Amit Cohen)  [Orabug: 34481188]
    - mlxsw: reg: Adjust PPCNT register to support local port 255 (Amit Cohen)  [Orabug: 34481188]
    - mlxsw: reg: Increase 'port_num' field in PMTDB register (Amit Cohen)  [Orabug: 34481188]
    - mlxsw: reg: Align existing registers to use extended local_port field (Amit Cohen)  [Orabug: 34481188]
    - mlxsw: item: Add support for local_port field in a split form (Amit Cohen)  [Orabug: 34481188]
    - mlxsw: reg: Remove unused functions (Amit Cohen)  [Orabug: 34481188]
    - mlxsw: spectrum: Bump minimum FW version to xx.2010.1006 (Amit Cohen)  [Orabug: 34481188]
    - devlink: Simplify devlink resources unregister call (Leon Romanovsky)  [Orabug: 34481188]
    - mlxsw: spectrum_router: Remove deadcode in mlxsw_sp_rif_mac_profile_find (Danielle Ratson)  [Orabug:
    34481188]
    - devlink: Add 'enable_iwarp' generic device param (Shiraz Saleem)  [Orabug: 34481188]
    - mlxsw: constify address in mlxsw_sp_port_dev_addr_set (Jakub Kicinski)  [Orabug: 34481188]
    - stmmac: fix build due to brainos in trans_start changes (Alexander Lobakin)  [Orabug: 34481188]
    - net: annotate accesses to queue->trans_start (Eric Dumazet)  [Orabug: 34481188]
    - net/mlx5: E-switch, Create QoS on demand (Dmytro Linkin)  [Orabug: 34481188]
    - net/mlx5: E-switch, Enable vport QoS on demand (Dmytro Linkin)  [Orabug: 34481188]
    - net/mlx5: E-switch, move offloads mode callbacks to offloads file (Parav Pandit)  [Orabug: 34481188]
    - net/mlx5: E-switch, Reuse mlx5_eswitch_set_vport_mac (Parav Pandit)  [Orabug: 34481188]
    - net/mlx5: E-switch, Remove vport enabled check (Parav Pandit)  [Orabug: 34481188]
    - net/mlx5e: Specify out ifindex when looking up decap route (Chris Mi)  [Orabug: 34481188]
    - net/mlx5e: TC, Move comment about mod header flag to correct place (Roi Dayan)  [Orabug: 34481188]
    - net/mlx5e: TC, Move kfree() calls after destroying all resources (Roi Dayan)  [Orabug: 34481188]
    - net/mlx5e: TC, Destroy nic flow counter if exists (Roi Dayan)  [Orabug: 34481188]
    - net/mlx5: TC, using swap() instead of tmp variable (Yihao Han)  [Orabug: 34481188]
    - net/mlx5: CT: Allow static allocation of mod headers (Paul Blakey)  [Orabug: 34481188]
    - net/mlx5e: Refactor mod header management API (Paul Blakey)  [Orabug: 34481188]
    - net/mlx5: Avoid printing health buffer when firmware is unavailable (Aya Levin)  [Orabug: 34481188]
    - net/mlx5: Fix format-security build warnings (Saeed Mahameed)  [Orabug: 34481188]
    - net/mlx5e: Support ethtool cq mode (Saeed Mahameed)  [Orabug: 34481188]
    - netdevsim: move vfconfig to nsim_dev (Jakub Kicinski)  [Orabug: 34481188]
    - netdevsim: take rtnl_lock when assigning num_vfs (Jakub Kicinski)  [Orabug: 34481188]
    - netdevsim: remove max_vfs dentry (Jakub Kicinski)  [Orabug: 34481188]
    - virtio_net: introduce TX timeout watchdog (Tony Lu)  [Orabug: 34481188]
    - net/mlx5e: TC, Fix memory leak with rules with internal port (Roi Dayan)  [Orabug: 34481188]
    - net/mlx5: Fix some error handling paths in 'mlx5e_tc_add_fdb_flow()' (Christophe JAILLET)  [Orabug:
    34481188]
    - net/mlx5e: Fix skb memory leak when TC classifier action offloads are disabled (Gal Pressman)  [Orabug:
    34481188]
    - net/mlx5: Fix tc max supported prio for nic mode (Chris Mi)  [Orabug: 34481188]
    - net/mlx5: Use first online CPU instead of hard coded CPU (Shay Drory)  [Orabug: 34481188]
    - net/mlx5: DR, Fix querying eswitch manager vport for ECPF (Yevgeny Kliteynik)  [Orabug: 34481188]
    - mlxsw: spectrum_router: Consolidate MAC profiles when possible (Danielle Ratson)  [Orabug: 34481188]
    - net/mlx5e: SHAMPO, Fix constant expression result (Ben Ben-Ishay)  [Orabug: 34481188]
    - net/mlx5: Fix access to a non-supported register (Aya Levin)  [Orabug: 34481188]
    - net/mlx5: Fix too early queueing of log timestamp work (Gal Pressman)  [Orabug: 34481188]
    - net/mlx5: Fix use after free in mlx5_health_wait_pci_up (Amir Tzin)  [Orabug: 34481188]
    - net/mlx5: E-Switch, Use indirect table only if all destinations support it (Maor Dickman)  [Orabug:
    34481188]
    - net/mlx5: Lag, Fix recreation of VF LAG (Maor Gottlieb)  [Orabug: 34481188]
    - mlxsw: spectrum: Allow driver to load with old firmware versions (Danielle Ratson)  [Orabug: 34481188]
    - RDMA/nldev: Check stat attribute before accessing it (Leon Romanovsky)  [Orabug: 34481188]
    - net/mlx5: Fix flow counters SF bulk query len (Avihai Horon)  [Orabug: 34481188]
    - net/mlx5: DR, Fix check for unsupported fields in match param (Yevgeny Kliteynik)  [Orabug: 34481188]
    - net/mlx5: DR, Handle eswitch manager and uplink vports separately (Yevgeny Kliteynik)  [Orabug:
    34481188]
    - net/mlx5: Lag, fix a potential Oops with mlx5_lag_create_definer() (Dan Carpenter)  [Orabug: 34481188]
    - net/mlx5: Support internal port as decap route device (Ariel Levkovich)  [Orabug: 34481188]
    - net/mlx5e: Term table handling of internal port rules (Ariel Levkovich)  [Orabug: 34481188]
    - net/mlx5e: Add indirect tc offload of ovs internal port (Ariel Levkovich)  [Orabug: 34481188]
    - net/mlx5e: Offload internal port as encap route device (Ariel Levkovich)  [Orabug: 34481188]
    - net/mlx5e: Offload tc rules that redirect to ovs internal port (Ariel Levkovich)  [Orabug: 34481188]
    - net/mlx5e: Accept action skbedit in the tc actions list (Ariel Levkovich)  [Orabug: 34481188]
    - net/mlx5: E-Switch, Add ovs internal port mapping to metadata support (Ariel Levkovich)  [Orabug:
    34481188]
    - net/mlx5e: Use generic name for the forwarding dev pointer (Ariel Levkovich)  [Orabug: 34481188]
    - net/mlx5e: Refactor rx handler of represetor device (Ariel Levkovich)  [Orabug: 34481188]
    - net/mlx5: DR, Add check for unsupported fields in match param (Muhammad Sammar)  [Orabug: 34481188]
    - net/mlx5: Allow skipping counter refresh on creation (Paul Blakey)  [Orabug: 34481188]
    - net/mlx5: CT: Remove warning of ignore_flow_level support for VFs (Paul Blakey)  [Orabug: 34481188]
    - net/mlx5: Add esw assignment back in mlx5e_tc_sample_unoffload() (Nathan Chancellor)  [Orabug: 34481188]
    - net: mellanox: mlxbf_gige: Replace non-standard interrupt handling (Asmaa Mnebhi)  [Orabug: 34481188]
    - mlxsw: spectrum_qdisc: Offload root TBF as port shaper (Petr Machata)  [Orabug: 34481188]
    - RDMA/core: Fix missed initialization of rdma_hw_stats::lock (Mark Zhang)  [Orabug: 34481188]
    - RDMA/umem: Allow pinned dmabuf umem usage (Gal Pressman)  [Orabug: 34481188]
    - net/mlx5: Lag, Make mlx5_lag_is_multipath() be static inline (Maor Dickman)  [Orabug: 34481188]
    - net/mlx5e: Prevent HW-GRO and CQE-COMPRESS features operate together (Khalid Manaa)  [Orabug: 34481188]
    - net/mlx5e: Add HW-GRO offload (Khalid Manaa)  [Orabug: 34481188]
    - net/mlx5e: Add HW_GRO statistics (Khalid Manaa)  [Orabug: 34481188]
    - net/mlx5e: HW_GRO cqe handler implementation (Khalid Manaa)  [Orabug: 34481188]
    - net/mlx5e: Add data path for SHAMPO feature (Ben Ben-Ishay)  [Orabug: 34481188]
    - net/mlx5e: Add handle SHAMPO cqe support (Khalid Manaa)  [Orabug: 34481188]
    - net/mlx5e: Add control path for SHAMPO feature (Ben Ben-Ishay)  [Orabug: 34481188]
    - net/mlx5e: Add support to klm_umr_wqe (Ben Ben-Ishay)  [Orabug: 34481188]
    - net/mlx5: Add SHAMPO caps, HW bits and enumerations (Ben Ben-Ishay)  [Orabug: 34481188]
    - lib: bitmap: Introduce node-aware alloc API (Tariq Toukan)  [Orabug: 34481188]
    - net/mlx5: remove the recent devlink params (Jakub Kicinski)  [Orabug: 34481188]
    - mlxsw: spectrum_router: Expose RIF MAC profiles to devlink resource (Danielle Ratson)  [Orabug:
    34481188]
    - mlxsw: spectrum_router: Add RIF MAC profiles support (Danielle Ratson)  [Orabug: 34481188]
    - mlxsw: spectrum_router: Propagate extack further (Danielle Ratson)  [Orabug: 34481188]
    - mlxsw: resources: Add resource identifier for RIF MAC profiles (Danielle Ratson)  [Orabug: 34481188]
    - mlxsw: reg: Add MAC profile ID field to RITR register (Danielle Ratson)  [Orabug: 34481188]
    - net/mlx5: SF_DEV Add SF device trace points (Parav Pandit)  [Orabug: 34481188]
    - net/mlx5: SF, Add SF trace points (Parav Pandit)  [Orabug: 34481188]
    - net/mlx5: Let user configure max_macs param (Shay Drory)  [Orabug: 34481188]
    - net/mlx5: Let user configure event_eq_size param (Shay Drory)  [Orabug: 34481188]
    - net/mlx5: Let user configure io_eq_size param (Shay Drory)  [Orabug: 34481188]
    - net/mlx5: Bridge, support replacing existing FDB entry (Vlad Buslov)  [Orabug: 34481188]
    - net/mlx5: Bridge, extract code to lookup and del/notify entry (Vlad Buslov)  [Orabug: 34481188]
    - net/mlx5: Add periodic update of host time to firmware (Aya Levin)  [Orabug: 34481188]
    - net/mlx5: Print health buffer by log level (Aya Levin)  [Orabug: 34481188]
    - net/mlx5: Extend health buffer dump (Aya Levin)  [Orabug: 34481188]
    - net/mlx5: Reduce flow counters bulk query buffer size for SFs (Avihai Horon)  [Orabug: 34481188]
    - net/mlx5: Fix unused function warning of mlx5i_flow_type_mask (Shay Drory)  [Orabug: 34481188]
    - net/mlx5: Remove unnecessary checks for slow path flag (Paul Blakey)  [Orabug: 34481188]
    - net/mlx5e: don't write directly to netdev->dev_addr (Jakub Kicinski)  [Orabug: 34481188]
    - RDMA/mlx5: Use dev_addr_mod() (Jakub Kicinski)  [Orabug: 34481188]
    - mlxsw: spectrum: Use 'bitmap_zalloc()' when applicable (Christophe JAILLET)  [Orabug: 34481188]
    - dma-buf: move dma-buf symbols into the DMA_BUF module namespace (Greg Kroah-Hartman)  [Orabug: 34481188]
    - net: convert users of bitmap_foo() to linkmode_foo() (Sean Anderson)  [Orabug: 34481188]
    - mlx5: fix build after merge (Jakub Kicinski)  [Orabug: 34481188]
    - ethernet: mlxsw: use eth_hw_addr_gen() (Jakub Kicinski)  [Orabug: 34481188]
    - RDMA/mlx5: Move struct mlx5_core_mkey to mlx5_ib (Aharon Landau)  [Orabug: 34481188]
    - RDMA/mlx5: Replace struct mlx5_core_mkey by u32 key (Aharon Landau)  [Orabug: 34481188]
    - RDMA/mlx5: Remove pd from struct mlx5_core_mkey (Aharon Landau)  [Orabug: 34481188]
    - RDMA/mlx5: Remove size from struct mlx5_core_mkey (Aharon Landau)  [Orabug: 34481188]
    - RDMA/mlx5: Remove iova from struct mlx5_core_mkey (Aharon Landau)  [Orabug: 34481188]
    - mlxsw: spectrum_qdisc: Make RED, TBF offloads classful (Petr Machata)  [Orabug: 34481188]
    - mlxsw: spectrum_qdisc: Validate qdisc topology (Petr Machata)  [Orabug: 34481188]
    - mlxsw: spectrum_qdisc: Clean stats recursively when priomap changes (Petr Machata)  [Orabug: 34481188]
    - mlxsw: spectrum_qdisc: Unify graft validation (Petr Machata)  [Orabug: 34481188]
    - mlxsw: spectrum_qdisc: Destroy children in mlxsw_sp_qdisc_destroy() (Petr Machata)  [Orabug: 34481188]
    - mlxsw: spectrum_qdisc: Extract two helpers for handling future FIFOs (Petr Machata)  [Orabug: 34481188]
    - mlxsw: spectrum_qdisc: Query tclass / priomap instead of caching it (Petr Machata)  [Orabug: 34481188]
    - net/mlx5: E-Switch, Increase supported number of forward destinations to 32 (Maor Dickman)  [Orabug:
    34481188]
    - net/mlx5: E-Switch, Use dynamic alloc for dest array (Maor Dickman)  [Orabug: 34481188]
    - net/mlx5: Lag, use steering to select the affinity port in LAG (Maor Gottlieb)  [Orabug: 34481188]
    - net/mlx5: Lag, add support to create/destroy/modify port selection (Maor Gottlieb)  [Orabug: 34481188]
    - net/mlx5: Lag, add support to create TTC tables for LAG port selection (Maor Gottlieb)  [Orabug:
    34481188]
    - net/mlx5: Lag, add support to create definers for LAG (Maor Gottlieb)  [Orabug: 34481188]
    - net/mlx5: Lag, set match mask according to the traffic type bitmap (Maor Gottlieb)  [Orabug: 34481188]
    - net/mlx5: Lag, set LAG traffic type mapping (Maor Gottlieb)  [Orabug: 34481188]
    - net/mlx5: Lag, move lag files into directory (Maor Gottlieb)  [Orabug: 34481188]
    - net/mlx5: Introduce new uplink destination type (Maor Gottlieb)  [Orabug: 34481188]
    - net/mlx5: Add support to create match definer (Maor Gottlieb)  [Orabug: 34481188]
    - net/mlx5: Introduce port selection namespace (Maor Gottlieb)  [Orabug: 34481188]
    - net/mlx5: Support partial TTC rules (Maor Gottlieb)  [Orabug: 34481188]
    - mlx5: prevent 64bit divide (Jakub Kicinski)  [Orabug: 34481188]
    - habanalabs: add support for dma-buf exporter (Tomer Tayar)  [Orabug: 34481188]
    - net/mlx5: Use system_image_guid to determine bonding (Rongwei Liu)  [Orabug: 34481188]
    - net/mlx5: Use native_port_num as 1st option of device index (Rongwei Liu)  [Orabug: 34481188]
    - net/mlx5: Introduce new device index wrapper (Rongwei Liu)  [Orabug: 34481188]
    - net/mlx5: Check return status first when querying system_image_guid (Rongwei Liu)  [Orabug: 34481188]
    - net/mlx5: DR, Prefer kcalloc over open coded arithmetic (Len Baker)  [Orabug: 34481188]
    - net/mlx5e: Add extack msgs related to TC for better debug (Abhiram R N)  [Orabug: 34481188]
    - net/mlx5: CT: Fix missing cleanup of ct nat table on init failure (Paul Blakey)  [Orabug: 34481188]
    - net/mlx5: Disable roce at HCA level (Shay Drory)  [Orabug: 34481188]
    - net/mlx5i: Enable Rx steering for IPoIB via ethtool (Moosa Baransi)  [Orabug: 34481188]
    - net/mlx5: Bridge, provide flow source hints (Vlad Buslov)  [Orabug: 34481188]
    - net/mlx5: Read timeout values from DTOR (Amir Tzin)  [Orabug: 34481188]
    - net/mlx5: Read timeout values from init segment (Amir Tzin)  [Orabug: 34481188]
    - net/mlx5: Add layout to support default timeouts register (Amir Tzin)  [Orabug: 34481188]
    - ethernet: constify references to netdev->dev_addr in drivers (Jakub Kicinski)  [Orabug: 34481188]
    - mlxsw: spectrum_qdisc: Introduce per-TC ECN counters (Petr Machata)  [Orabug: 34481188]
    - mlxsw: reg: Add ecn_marked_tc to Per-TC Congestion Counters (Petr Machata)  [Orabug: 34481188]
    - mlxsw: reg: Rename MLXSW_REG_PPCNT_TC_CONG_TC to _CNT (Petr Machata)  [Orabug: 34481188]
    - mlxsw: reg: Fix a typo in a group heading (Petr Machata)  [Orabug: 34481188]
    - devlink: Don't throw an error if flash notification sent before devlink visible (Leon Romanovsky)
    [Orabug: 34481188]
    - devlink: fix flexible_array.cocci warning (Guo Zhengkui)  [Orabug: 34481188]
    - ethtool: don't drop the rtnl_lock half way thru the ioctl (Jakub Kicinski)  [Orabug: 34481188]
    - devlink: expose get/put functions (Jakub Kicinski)  [Orabug: 34481188]
    - ethtool: handle info/flash data copying outside rtnl_lock (Jakub Kicinski)  [Orabug: 34481188]
    - ethtool: push the rtnl_lock into dev_ethtool() (Jakub Kicinski)  [Orabug: 34481188]
    - devlink: make all symbols GPL-only (Jakub Kicinski)  [Orabug: 34481188]
    - devlink: Simplify internal devlink params implementation (Leon Romanovsky)  [Orabug: 34481188]

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2023-12226.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-2196");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:9");
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

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  var fixed_uptrack_levels = ['5.15.0-100.96.32.el8uek', '5.15.0-100.96.32.el9uek'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2023-12226');
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
    {'reference':'bpftool-5.15.0-100.96.32.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'bpftool-5.15.0'},
    {'reference':'kernel-uek-5.15.0-100.96.32.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-5.15.0'},
    {'reference':'kernel-uek-core-5.15.0-100.96.32.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-core-5.15.0'},
    {'reference':'kernel-uek-debug-5.15.0-100.96.32.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-5.15.0'},
    {'reference':'kernel-uek-debug-core-5.15.0-100.96.32.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-core-5.15.0'},
    {'reference':'kernel-uek-debug-devel-5.15.0-100.96.32.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-5.15.0'},
    {'reference':'kernel-uek-debug-modules-5.15.0-100.96.32.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-modules-5.15.0'},
    {'reference':'kernel-uek-debug-modules-extra-5.15.0-100.96.32.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-modules-extra-5.15.0'},
    {'reference':'kernel-uek-devel-5.15.0-100.96.32.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-5.15.0'},
    {'reference':'kernel-uek-doc-5.15.0-100.96.32.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-5.15.0'},
    {'reference':'kernel-uek-modules-5.15.0-100.96.32.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-modules-5.15.0'},
    {'reference':'kernel-uek-modules-extra-5.15.0-100.96.32.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-modules-extra-5.15.0'},
    {'reference':'bpftool-5.15.0-100.96.32.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'bpftool-5.15.0'},
    {'reference':'kernel-uek-5.15.0-100.96.32.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-5.15.0'},
    {'reference':'kernel-uek-container-5.15.0-100.96.32.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-container-5.15.0'},
    {'reference':'kernel-uek-container-debug-5.15.0-100.96.32.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-container-debug-5.15.0'},
    {'reference':'kernel-uek-core-5.15.0-100.96.32.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-core-5.15.0'},
    {'reference':'kernel-uek-debug-5.15.0-100.96.32.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-5.15.0'},
    {'reference':'kernel-uek-debug-core-5.15.0-100.96.32.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-core-5.15.0'},
    {'reference':'kernel-uek-debug-devel-5.15.0-100.96.32.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-5.15.0'},
    {'reference':'kernel-uek-debug-modules-5.15.0-100.96.32.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-modules-5.15.0'},
    {'reference':'kernel-uek-debug-modules-extra-5.15.0-100.96.32.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-modules-extra-5.15.0'},
    {'reference':'kernel-uek-devel-5.15.0-100.96.32.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-5.15.0'},
    {'reference':'kernel-uek-doc-5.15.0-100.96.32.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-5.15.0'},
    {'reference':'kernel-uek-modules-5.15.0-100.96.32.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-modules-5.15.0'},
    {'reference':'kernel-uek-modules-extra-5.15.0-100.96.32.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-modules-extra-5.15.0'},
    {'reference':'bpftool-5.15.0-100.96.32.el9uek', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'bpftool-5.15.0'},
    {'reference':'kernel-uek-5.15.0-100.96.32.el9uek', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-5.15.0'},
    {'reference':'kernel-uek-core-5.15.0-100.96.32.el9uek', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-core-5.15.0'},
    {'reference':'kernel-uek-debug-5.15.0-100.96.32.el9uek', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-5.15.0'},
    {'reference':'kernel-uek-debug-core-5.15.0-100.96.32.el9uek', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-core-5.15.0'},
    {'reference':'kernel-uek-debug-devel-5.15.0-100.96.32.el9uek', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-5.15.0'},
    {'reference':'kernel-uek-debug-modules-5.15.0-100.96.32.el9uek', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-modules-5.15.0'},
    {'reference':'kernel-uek-debug-modules-extra-5.15.0-100.96.32.el9uek', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-modules-extra-5.15.0'},
    {'reference':'kernel-uek-devel-5.15.0-100.96.32.el9uek', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-5.15.0'},
    {'reference':'kernel-uek-doc-5.15.0-100.96.32.el9uek', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-5.15.0'},
    {'reference':'kernel-uek-modules-5.15.0-100.96.32.el9uek', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-modules-5.15.0'},
    {'reference':'kernel-uek-modules-extra-5.15.0-100.96.32.el9uek', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-modules-extra-5.15.0'},
    {'reference':'bpftool-5.15.0-100.96.32.el9uek', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'bpftool-5.15.0'},
    {'reference':'kernel-uek-5.15.0-100.96.32.el9uek', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-5.15.0'},
    {'reference':'kernel-uek-core-5.15.0-100.96.32.el9uek', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-core-5.15.0'},
    {'reference':'kernel-uek-debug-5.15.0-100.96.32.el9uek', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-5.15.0'},
    {'reference':'kernel-uek-debug-core-5.15.0-100.96.32.el9uek', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-core-5.15.0'},
    {'reference':'kernel-uek-debug-devel-5.15.0-100.96.32.el9uek', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-5.15.0'},
    {'reference':'kernel-uek-debug-modules-5.15.0-100.96.32.el9uek', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-modules-5.15.0'},
    {'reference':'kernel-uek-debug-modules-extra-5.15.0-100.96.32.el9uek', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-modules-extra-5.15.0'},
    {'reference':'kernel-uek-devel-5.15.0-100.96.32.el9uek', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-5.15.0'},
    {'reference':'kernel-uek-doc-5.15.0-100.96.32.el9uek', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-5.15.0'},
    {'reference':'kernel-uek-modules-5.15.0-100.96.32.el9uek', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-modules-5.15.0'},
    {'reference':'kernel-uek-modules-extra-5.15.0-100.96.32.el9uek', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-modules-extra-5.15.0'}
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
