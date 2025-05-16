#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2024:1979-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(200401);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/01");

  script_cve_id(
    "CVE-2021-46933",
    "CVE-2021-47074",
    "CVE-2021-47162",
    "CVE-2021-47171",
    "CVE-2021-47188",
    "CVE-2021-47206",
    "CVE-2021-47220",
    "CVE-2021-47229",
    "CVE-2021-47231",
    "CVE-2021-47235",
    "CVE-2021-47236",
    "CVE-2021-47237",
    "CVE-2021-47238",
    "CVE-2021-47239",
    "CVE-2021-47245",
    "CVE-2021-47246",
    "CVE-2021-47248",
    "CVE-2021-47249",
    "CVE-2021-47250",
    "CVE-2021-47252",
    "CVE-2021-47254",
    "CVE-2021-47258",
    "CVE-2021-47260",
    "CVE-2021-47261",
    "CVE-2021-47265",
    "CVE-2021-47269",
    "CVE-2021-47274",
    "CVE-2021-47276",
    "CVE-2021-47277",
    "CVE-2021-47280",
    "CVE-2021-47281",
    "CVE-2021-47284",
    "CVE-2021-47285",
    "CVE-2021-47288",
    "CVE-2021-47301",
    "CVE-2021-47302",
    "CVE-2021-47305",
    "CVE-2021-47307",
    "CVE-2021-47308",
    "CVE-2021-47310",
    "CVE-2021-47311",
    "CVE-2021-47314",
    "CVE-2021-47315",
    "CVE-2021-47319",
    "CVE-2021-47320",
    "CVE-2021-47321",
    "CVE-2021-47323",
    "CVE-2021-47324",
    "CVE-2021-47330",
    "CVE-2021-47334",
    "CVE-2021-47337",
    "CVE-2021-47343",
    "CVE-2021-47344",
    "CVE-2021-47345",
    "CVE-2021-47347",
    "CVE-2021-47352",
    "CVE-2021-47353",
    "CVE-2021-47355",
    "CVE-2021-47356",
    "CVE-2021-47357",
    "CVE-2021-47361",
    "CVE-2021-47362",
    "CVE-2021-47369",
    "CVE-2021-47375",
    "CVE-2021-47378",
    "CVE-2021-47382",
    "CVE-2021-47383",
    "CVE-2021-47391",
    "CVE-2021-47397",
    "CVE-2021-47400",
    "CVE-2021-47401",
    "CVE-2021-47404",
    "CVE-2021-47409",
    "CVE-2021-47416",
    "CVE-2021-47423",
    "CVE-2021-47424",
    "CVE-2021-47431",
    "CVE-2021-47435",
    "CVE-2021-47436",
    "CVE-2021-47456",
    "CVE-2021-47458",
    "CVE-2021-47460",
    "CVE-2021-47469",
    "CVE-2021-47472",
    "CVE-2021-47473",
    "CVE-2021-47478",
    "CVE-2021-47480",
    "CVE-2021-47483",
    "CVE-2021-47485",
    "CVE-2021-47495",
    "CVE-2021-47496",
    "CVE-2021-47497",
    "CVE-2021-47500",
    "CVE-2021-47506",
    "CVE-2021-47509",
    "CVE-2021-47511",
    "CVE-2021-47523",
    "CVE-2021-47541",
    "CVE-2021-47548",
    "CVE-2021-47565",
    "CVE-2022-48686",
    "CVE-2022-48697",
    "CVE-2022-48704",
    "CVE-2022-48708",
    "CVE-2022-48710",
    "CVE-2023-0160",
    "CVE-2023-1829",
    "CVE-2023-42755",
    "CVE-2023-47233",
    "CVE-2023-52527",
    "CVE-2023-52586",
    "CVE-2023-52591",
    "CVE-2023-52655",
    "CVE-2023-52664",
    "CVE-2023-52685",
    "CVE-2023-52686",
    "CVE-2023-52691",
    "CVE-2023-52696",
    "CVE-2023-52698",
    "CVE-2023-52703",
    "CVE-2023-52730",
    "CVE-2023-52732",
    "CVE-2023-52741",
    "CVE-2023-52742",
    "CVE-2023-52747",
    "CVE-2023-52759",
    "CVE-2023-52774",
    "CVE-2023-52781",
    "CVE-2023-52796",
    "CVE-2023-52803",
    "CVE-2023-52821",
    "CVE-2023-52864",
    "CVE-2023-52865",
    "CVE-2023-52867",
    "CVE-2023-52875",
    "CVE-2023-52880",
    "CVE-2024-26625",
    "CVE-2024-26752",
    "CVE-2024-26775",
    "CVE-2024-26828",
    "CVE-2024-26846",
    "CVE-2024-26874",
    "CVE-2024-26900",
    "CVE-2024-26915",
    "CVE-2024-26920",
    "CVE-2024-26921",
    "CVE-2024-26934",
    "CVE-2024-26957",
    "CVE-2024-26958",
    "CVE-2024-26984",
    "CVE-2024-26996",
    "CVE-2024-27059",
    "CVE-2024-27062",
    "CVE-2024-27396",
    "CVE-2024-27398",
    "CVE-2024-27401",
    "CVE-2024-27419",
    "CVE-2024-27436",
    "CVE-2024-35789",
    "CVE-2024-35791",
    "CVE-2024-35809",
    "CVE-2024-35811",
    "CVE-2024-35830",
    "CVE-2024-35849",
    "CVE-2024-35877",
    "CVE-2024-35878",
    "CVE-2024-35887",
    "CVE-2024-35895",
    "CVE-2024-35914",
    "CVE-2024-35932",
    "CVE-2024-35935",
    "CVE-2024-35936",
    "CVE-2024-35944",
    "CVE-2024-35955",
    "CVE-2024-35969",
    "CVE-2024-35982",
    "CVE-2024-35984",
    "CVE-2024-36015",
    "CVE-2024-36029",
    "CVE-2024-36954"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2024:1979-1");

  script_name(english:"SUSE SLES12 Security Update : kernel (SUSE-SU-2024:1979-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES12 / SLES_SAP12 host has packages installed that are affected by multiple vulnerabilities as
referenced in the SUSE-SU-2024:1979-1 advisory.

    The SUSE Linux Enterprise 12 SP5 Azure kernel was updated to receive various security bugfixes.

    The following security bugs were fixed:

    - CVE-2024-26921: Preserve kabi for sk_buff (bsc#1223138).
    - CVE-2022-48686: Fix UAF when detecting digest errors (bsc#1223948). Update blacklist.conf: remove entry
    - CVE-2021-47074: Fixed memory leak in nvme_loop_create_ctrl() (bsc#1220854).
    - CVE-2021-47378: Destroy cm id before destroy qp to avoid use after free (bsc#1225201).
    - CVE-2022-48697: Fix a use-after-free (bsc#1223922). Update blacklist.conf: drop entry from it
    - CVE-2024-26846: Do not wait in vain when unloading module (bsc#1223023).
    - CVE-2021-47496: Fix flipped sign in tls_err_abort() calls (bsc#1225354)
    - CVE-2023-42755: Check user supplied offsets (bsc#1215702).
    - CVE-2023-52664: Eliminate double free in error handling logic (bsc#1224747).
    - CVE-2023-52796: Add ipvlan_route_v6_outbound() helper (bsc#1224930).
    - CVE-2021-47246: Fix page reclaim for dead peer hairpin (bsc#1224831).
    - CVE-2023-52732: Blocklist the kclient when receiving corrupted snap trace (bsc#1225222 CVE-2023-52732).
    - CVE-2024-35936: Add missing mutex_unlock in btrfs_relocate_sys_chunks() (bsc#1224644)
    - CVE-2021-47548: Fixed a possible array out-of=bounds (bsc#1225506)
    - CVE-2024-36029: Pervent access to suspended controller (bsc#1225708 CVE-2024-36029)
    - CVE-2024-26625: Call sock_orphan() at release time (bsc#1221086)
    - CVE-2021-47352: Add validation for used length (bsc#1225124).
    - CVE-2023-52698: Fixed memory leak in netlbl_calipso_add_pass() (bsc#1224621)
    - CVE-2021-47431: Fix gart.bo pin_count leak (bsc#1225390).
    - CVE-2024-35935: Handle path ref underflow in header iterate_inode_ref() (bsc#1224645)
    - CVE-2024-26828: Fixed underflow in parse_server_interfaces() (bsc#1223084).
    - CVE-2021-47423: Fix file release memory leak (bsc#1225366).
    - CVE-2022-48710: Fix a possible null pointer dereference (bsc#1225230).
    - CVE-2021-47497: Fixed shift-out-of-bound (UBSAN) with byte size cells (bsc#1225355).
    - CVE-2024-35932: Do not check if plane->state->fb == state->fb (bsc#1224650).
    - CVE-2021-47500: Fixed trigger reference couting (bsc#1225360).
    - CVE-2024-35809: Drain runtime-idle callbacks before driver removal (bsc#1224738).
    - CVE-2021-47383: Fiedx out-of-bound vmalloc access in imageblit (bsc#1225208).
    - CVE-2021-47511: Fixed negative period/buffer sizes (bsc#1225411).
    - CVE-2021-47509: Limit the period size to 16MB (bsc#1225409).
    - CVE-2024-35877: Fixed VM_PAT handling in COW mappings (bsc#1224525).
    - CVE-2024-35982: Avoid infinite loop trying to resize local TT (bsc#1224566)
    - CVE-2024-35969: Fixed race condition between ipv6_get_ifaddr and ipv6_del_addr (bsc#1224580).
    - CVE-2021-47277: Avoid speculation-based attacks from out-of-range memslot accesses (bsc#1224960,
    CVE-2021-47277).
    - CVE-2024-35791: Flush pages under kvm->lock to fix UAF in svm_register_enc_region() (bsc#1224725).
    - CVE-2021-47401: Fix stack information leak (bsc#1225242).
    - CVE-2023-52867: Fix possible buffer overflow (bsc#1225009).
    - CVE-2023-52821: Fix a possible null pointer dereference (bsc#1225022).
    - CVE-2021-47265: Verify port when creating flow rule (bsc#1224957)
    - CVE-2021-47362: Update intermediate power state for SI (bsc#1225153).
    - CVE-2021-47361: Fix error handling in mcb_alloc_bus() (bsc#1225151).
    - CVE-2023-52864: Fix opening of char device (bsc#1225132).
    - CVE-2022-48708: Fix potential NULL dereference (bsc#1224942).
    - CVE-2024-35944: Fixed memcpy() run-time warning in dg_dispatch_as_host() (bsc#1224648).
    - CVE-2021-47238: Fix memory leak in ip_mc_add1_src (bsc#1224847)
    - CVE-2023-52730: Fix possible resource leaks in some error paths (bsc#1224956).
    - CVE-2021-47355: Fix possible use-after-free in nicstar_cleanup() (bsc#1225141).
    - CVE-2021-47245: Fix out of bounds when parsing TCP options (bsc#1224838)
    - CVE-2024-35878: Prevent NULL pointer dereference in vsnprintf() (bsc#1224671).
    - CVE-2023-52747: Restore allocated resources on failed copyout (bsc#1224931)
    - CVE-2021-47249: Fix memory leak in rds_recvmsg (bsc#1224880)
    - CVE-2021-47397: Break out if skb_header_pointer returns NULL in sctp_rcv_ootb (bsc#1225082)
    - CVE-2021-47250: Fix memory leak in netlbl_cipsov4_add_std (bsc#1224827)
    - CVE-2024-35849: Fix information leak in btrfs_ioctl_logical_to_ino() (bsc#1224733).
    - CVE-2024-27436: Stop parsing channels bits when all channels are found (bsc#1224803).
    - CVE-2021-47281: Fix race of snd_seq_timer_open() (bsc#1224983).
    - CVE-2024-35789: Clear fast rx for non-4addr in VLAN netdev (bsc#1224749).
    - CVE-2024-35830: Register v4l2 async device only after successful setup (bsc#1224680).
    - CVE-2021-47334: Fix two use after free in ibmasm_init_one (bsc#1225112).
    - CVE-2021-47357: Fix possible use-after-free in ia_module_exit() (bsc#1225144).
    - CVE-2023-52875: Add check for mtk_alloc_clk_data (bsc#1225096).
    - CVE-2023-52865: Add check for mtk_alloc_clk_data (bsc#1225086).
    - CVE-2024-35887: Fix use-after-free bugs caused by ax25_ds_del_timer (bsc#1224663)
    - CVE-2021-47483: Fixed possible double-free in regcache_rbtree_exit() (bsc#1224907).
    - CVE-2024-26957: Fix reference counting on zcrypt card objects (bsc#1223666).
    - CVE-2023-52691: Fix a double-free in si_dpm_init (bsc#1224607).
    - CVE-2024-27398: Fixed use-after-free bugs caused by sco_sock_timeout (bsc#1224174).
    - CVE-2023-52586: Fixed mutex lock in control vblank irq (bsc#1221081).
    - CVE-2024-27062: Fixed nouveau lock inside client object tree (bsc#1223834).
    - CVE-2024-26984: Fix instmem race condition around ptr stores (bsc#1223633)
    - CVE-2021-46933: Fixed possible underflow in ffs_data_clear() (bsc#1220487).
    - CVE-2024-27396: Fixed Use-After-Free in gtp_dellink (bsc#1224096).
    - CVE-2023-52655: Check packet for fixup for true limit (bsc#1217169).
    - CVE-2024-26900: Fixed kmemleak of rdev->serial (bsc#1223046).
    - CVE-2024-27401: Fixed user_length taken into account when fetching packet contents (bsc#1224181).
    - CVE-2024-26775: Fixed potential deadlock at set_capacity (bsc#1222627).
    - CVE-2024-26958: Fixed UAF in direct writes (bsc#1223653).
    - CVE-2022-48704: Add a force flush to delay work when radeon (bsc#1223932)
    - CVE-2021-47206: Check return value after calling platform_get_resource() (bsc#1222894).
    - CVE-2024-26915: Reset IH OVERFLOW_CLEAR bit (bsc#1223207)
    - CVE-2024-26996: Fix UAF ncm object at re-bind after usb transport error (bsc#1223752).
    - CVE-2024-26874: Fix a null pointer crash in mtk_drm_crtc_finish_page_flip (bsc#1223048)
    - CVE-2023-1829: Fixed a use-after-free vulnerability in the control index filter (tcindex) (bsc#1210335).


Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1065729");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1101816");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1181674");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185902");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187716");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188616");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190317");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190795");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191452");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194591");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197760");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206213");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206646");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207186");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209657");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210335");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215702");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1216702");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217169");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217519");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220487");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220854");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220928");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221044");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221081");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221086");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221977");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221994");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222619");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222627");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222667");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222671");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222893");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222894");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223023");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223046");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223048");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223084");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223138");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223207");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223360");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223384");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223633");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223653");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223666");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223671");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223738");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223752");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223834");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223922");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223932");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223948");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224096");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224174");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224181");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224347");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224482");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224511");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224525");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224566");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224580");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224592");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224601");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224607");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224621");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224644");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224645");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224648");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224650");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224663");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224671");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224676");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224680");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224682");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224725");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224728");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224733");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224738");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224747");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224749");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224759");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224803");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224827");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224830");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224831");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224834");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224838");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224841");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224844");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224846");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224847");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224849");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224854");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224859");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224867");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224880");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224882");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224888");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224889");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224892");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224893");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224899");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224904");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224907");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224916");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224917");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224922");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224926");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224930");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224931");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224942");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224954");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224957");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224959");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224960");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224961");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224963");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224966");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224968");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224981");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224982");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224983");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224987");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224990");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224996");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225008");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225009");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225010");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225022");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225026");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225030");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225054");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225058");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225059");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225060");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225062");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225082");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225084");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225086");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225092");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225096");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225112");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225124");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225128");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225132");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225141");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225143");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225144");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225151");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225153");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225155");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225157");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225164");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225177");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225189");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225192");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225193");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225198");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225201");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225207");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225208");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225222");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225230");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225242");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225244");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225247");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225251");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225252");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225256");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225303");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225318");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225322");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225329");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225330");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225336");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225347");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225351");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225354");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225355");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225360");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225366");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225367");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225384");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225390");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225404");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225409");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225411");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225438");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225453");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225479");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225482");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225506");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225549");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225560");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225572");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225640");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225708");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225764");
  script_set_attribute(attribute:"see_also", value:"https://lists.suse.com/pipermail/sle-updates/2024-June/035536.html");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46933");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47074");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47162");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47171");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47188");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47206");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47220");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47229");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47231");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47235");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47236");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47237");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47238");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47239");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47245");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47246");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47248");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47249");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47250");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47252");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47254");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47258");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47260");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47261");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47265");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47269");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47274");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47276");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47277");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47280");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47281");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47284");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47285");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47288");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47301");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47302");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47305");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47307");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47308");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47310");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47311");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47314");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47315");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47319");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47320");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47321");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47323");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47324");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47330");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47334");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47337");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47343");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47344");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47345");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47347");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47352");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47353");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47355");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47356");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47357");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47361");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47362");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47369");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47375");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47378");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47382");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47383");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47391");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47397");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47400");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47401");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47404");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47409");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47416");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47423");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47424");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47431");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47435");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47436");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47456");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47458");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47460");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47469");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47472");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47473");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47478");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47480");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47483");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47485");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47495");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47496");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47497");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47500");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47506");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47509");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47511");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47523");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47541");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47548");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47565");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48686");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48697");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48704");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48708");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48710");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-0160");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1829");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-42755");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-47233");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52527");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52586");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52591");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52655");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52664");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52685");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52686");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52691");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52696");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52698");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52703");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52730");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52732");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52741");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52742");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52747");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52759");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52774");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52781");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52796");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52803");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52821");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52864");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52865");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52867");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52875");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52880");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26625");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26752");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26775");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26828");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26846");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26874");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26900");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26915");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26920");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26921");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26934");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26957");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26958");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26984");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26996");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27059");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27062");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27396");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27398");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27401");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27419");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27436");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35789");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35791");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35809");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35811");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35830");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35849");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35877");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35878");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35887");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35895");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35914");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35932");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35935");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35936");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35944");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35955");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35969");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35982");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35984");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36015");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36029");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36954");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-35887");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/06/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-azure-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-azure-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-devel-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-source-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms-azure");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
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
if (isnull(os_release) || os_release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)(?:_SAP)?\d+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES12|SLES_SAP12)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES12 / SLES_SAP12', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES12 SP5", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP12" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP12 SP5", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'kernel-azure-4.12.14-16.188.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'kernel-azure-base-4.12.14-16.188.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'kernel-azure-devel-4.12.14-16.188.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'kernel-devel-azure-4.12.14-16.188.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'kernel-source-azure-4.12.14-16.188.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'kernel-syms-azure-4.12.14-16.188.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'kernel-azure-4.12.14-16.188.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'kernel-azure-base-4.12.14-16.188.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'kernel-azure-devel-4.12.14-16.188.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'kernel-devel-azure-4.12.14-16.188.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'kernel-source-azure-4.12.14-16.188.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'kernel-syms-azure-4.12.14-16.188.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel-azure / kernel-azure-base / kernel-azure-devel / etc');
}
