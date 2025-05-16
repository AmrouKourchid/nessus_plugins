#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2024:4131-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(212537);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/12");

  script_cve_id(
    "CVE-2021-47416",
    "CVE-2021-47534",
    "CVE-2022-3435",
    "CVE-2022-45934",
    "CVE-2022-48664",
    "CVE-2022-48879",
    "CVE-2022-48946",
    "CVE-2022-48947",
    "CVE-2022-48948",
    "CVE-2022-48949",
    "CVE-2022-48951",
    "CVE-2022-48953",
    "CVE-2022-48954",
    "CVE-2022-48955",
    "CVE-2022-48956",
    "CVE-2022-48959",
    "CVE-2022-48960",
    "CVE-2022-48961",
    "CVE-2022-48962",
    "CVE-2022-48967",
    "CVE-2022-48968",
    "CVE-2022-48969",
    "CVE-2022-48970",
    "CVE-2022-48971",
    "CVE-2022-48972",
    "CVE-2022-48973",
    "CVE-2022-48975",
    "CVE-2022-48977",
    "CVE-2022-48978",
    "CVE-2022-48981",
    "CVE-2022-48985",
    "CVE-2022-48987",
    "CVE-2022-48988",
    "CVE-2022-48991",
    "CVE-2022-48992",
    "CVE-2022-48994",
    "CVE-2022-48995",
    "CVE-2022-48997",
    "CVE-2022-48999",
    "CVE-2022-49000",
    "CVE-2022-49002",
    "CVE-2022-49003",
    "CVE-2022-49005",
    "CVE-2022-49006",
    "CVE-2022-49007",
    "CVE-2022-49010",
    "CVE-2022-49011",
    "CVE-2022-49012",
    "CVE-2022-49014",
    "CVE-2022-49015",
    "CVE-2022-49016",
    "CVE-2022-49019",
    "CVE-2022-49021",
    "CVE-2022-49022",
    "CVE-2022-49023",
    "CVE-2022-49024",
    "CVE-2022-49025",
    "CVE-2022-49026",
    "CVE-2022-49027",
    "CVE-2022-49028",
    "CVE-2022-49029",
    "CVE-2022-49031",
    "CVE-2022-49032",
    "CVE-2023-2166",
    "CVE-2023-6270",
    "CVE-2023-28327",
    "CVE-2023-52766",
    "CVE-2023-52800",
    "CVE-2023-52881",
    "CVE-2023-52919",
    "CVE-2024-27043",
    "CVE-2024-42145",
    "CVE-2024-43854",
    "CVE-2024-44947",
    "CVE-2024-45013",
    "CVE-2024-45016",
    "CVE-2024-45026",
    "CVE-2024-46716",
    "CVE-2024-46813",
    "CVE-2024-46814",
    "CVE-2024-46815",
    "CVE-2024-46816",
    "CVE-2024-46817",
    "CVE-2024-46818",
    "CVE-2024-46849",
    "CVE-2024-47668",
    "CVE-2024-47674",
    "CVE-2024-47684",
    "CVE-2024-47706",
    "CVE-2024-47747",
    "CVE-2024-47748",
    "CVE-2024-49860",
    "CVE-2024-49867",
    "CVE-2024-49925",
    "CVE-2024-49930",
    "CVE-2024-49936",
    "CVE-2024-49945",
    "CVE-2024-49960",
    "CVE-2024-49969",
    "CVE-2024-49974",
    "CVE-2024-49982",
    "CVE-2024-49991",
    "CVE-2024-49995",
    "CVE-2024-50047",
    "CVE-2024-50208"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2024:4131-1");

  script_name(english:"SUSE SLES15 Security Update : kernel (SUSE-SU-2024:4131-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 / SLES_SAP15 host has packages installed that are affected by multiple vulnerabilities as
referenced in the SUSE-SU-2024:4131-1 advisory.

    The SUSE Linux Enterprise 15 SP4 kernel was updated to receive various security bugfixes.


    The following security bugs were fixed:

    - CVE-2024-43854: Initialize integrity buffer to zero before writing it to media (bsc#1229345)
    - CVE-2024-49925: fbdev: efifb: Register sysfs groups through driver core (bsc#1232224)
    - CVE-2024-49945: net/ncsi: Disable the ncsi work before freeing the associated structure (bsc#1232165).
    - CVE-2024-50208: RDMA/bnxt_re: Fix a bug while setting up Level-2 PBL pages (bsc#1233117).
    - CVE-2022-48879: efi: fix NULL-deref in init error path (bsc#1229556).
    - CVE-2022-48956: ipv6: avoid use-after-free in ip6_fragment() (bsc#1231893).
    - CVE-2022-48959: net: dsa: sja1105: fix memory leak in sja1105_setup_devlink_regions() (bsc#1231976).
    - CVE-2022-48960: net: hisilicon: Fix potential use-after-free in hix5hd2_rx() (bsc#1231979).
    - CVE-2022-48962: net: hisilicon: Fix potential use-after-free in hisi_femac_rx() (bsc#1232286).
    - CVE-2022-48991: mm/khugepaged: fix collapse_pte_mapped_thp() to allow anon_vma (bsc#1232070).
    - CVE-2022-49015: net: hsr: Fix potential use-after-free (bsc#1231938).
    - CVE-2024-45013: nvme: move stopping keep-alive into nvme_uninit_ctrl() (bsc#1230442).
    - CVE-2024-45016: netem: fix return value if duplicate enqueue fails (bsc#1230429).
    - CVE-2024-45026: s390/dasd: fix error recovery leading to data corruption on ESE devices (bsc#1230454).
    - CVE-2024-46716: dmaengine: altera-msgdma: properly free descriptor in msgdma_free_descriptor
    (bsc#1230715).
    - CVE-2024-46813: drm/amd/display: Check link_index before accessing dc->links (bsc#1231191).
    - CVE-2024-46814: drm/amd/display: Check msg_id before processing transcation (bsc#1231193).
    - CVE-2024-46815: drm/amd/display: Check num_valid_sets before accessing reader_wm_sets (bsc#1231195).
    - CVE-2024-46816: drm/amd/display: Stop amdgpu_dm initialize when link nums greater than max_links
    (bsc#1231197).
    - CVE-2024-46817: drm/amd/display: Stop amdgpu_dm initialize when stream nums greater than 6
    (bsc#1231200).
    - CVE-2024-46818: drm/amd/display: Check gpio_id before used as array index (bsc#1231203).
    - CVE-2024-46849: ASoC: meson: axg-card: fix 'use-after-free' (bsc#1231073).
    - CVE-2024-47668: lib/generic-radix-tree.c: Fix rare race in __genradix_ptr_alloc() (bsc#1231502).
    - CVE-2024-47674: mm: avoid leaving partial pfn mappings around in error case (bsc#1231673).
    - CVE-2024-47684: tcp: check skb is non-NULL in tcp_rto_delta_us() (bsc#1231987).
    - CVE-2024-47706: block, bfq: fix possible UAF for bfqq->bic with merge chain (bsc#1231942).
    - CVE-2024-47747: net: seeq: Fix use after free vulnerability in ether3 Driver Due to Race Condition
    (bsc#1232145).
    - CVE-2024-47748: vhost_vdpa: assign irq bypass producer token correctly (bsc#1232174).
    - CVE-2024-49860: ACPI: sysfs: validate return type of _STR method (bsc#1231861).
    - CVE-2024-49930: wifi: ath11k: fix array out-of-bound access in SoC stats (bsc#1232260).
    - CVE-2024-49936: net/xen-netback: prevent UAF in xenvif_flush_hash() (bsc#1232424).
    - CVE-2024-49960: ext4: fix timer use-after-free on failed mount (bsc#1232395).
    - CVE-2024-49969: drm/amd/display: Fix index out of bounds in DCN30 color transformation (bsc#1232519).
    - CVE-2024-49974: NFSD: Force all NFSv4.2 COPY requests to be synchronous (bsc#1232383).
    - CVE-2024-49991: drm/amdkfd: amdkfd_free_gtt_mem clear the correct pointer (bsc#1232282).
    - CVE-2024-49995: tipc: guard against string buffer overrun (bsc#1232432).
    - CVE-2024-50047: smb: client: fix UAF in async decryption (bsc#1232418).


Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204171");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205796");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206188");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206344");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209290");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210449");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210627");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213034");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1216223");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1216813");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218562");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220382");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223384");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223524");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223824");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225189");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225336");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225611");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226666");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228743");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229345");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229452");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229454");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229456");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229556");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230429");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230442");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230454");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230600");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230620");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230715");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230903");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231016");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231073");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231191");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231193");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231195");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231197");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231200");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231203");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231293");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231375");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231502");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231673");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231861");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231883");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231885");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231887");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231888");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231890");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231892");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231893");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231895");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231896");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231897");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231929");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231936");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231937");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231938");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231939");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231940");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231941");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231942");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231958");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231960");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231961");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231962");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231972");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231976");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231979");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231987");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231988");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231991");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231992");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231995");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231996");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231997");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232001");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232005");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232006");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232007");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232025");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232026");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232033");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232035");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232036");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232037");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232038");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232039");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232067");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232069");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232070");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232071");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232097");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232108");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232119");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232120");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232123");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232133");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232136");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232145");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232150");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232163");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232165");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232170");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232172");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232174");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232224");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232229");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232237");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232260");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232262");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232281");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232282");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232286");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232304");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232383");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232395");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232418");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232424");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232432");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232436");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232519");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233117");
  # https://lists.suse.com/pipermail/sle-security-updates/2024-December/019887.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?aa9e9a80");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47416");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47534");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3435");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-45934");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48664");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48879");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48946");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48947");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48948");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48949");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48951");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48953");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48954");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48955");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48956");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48959");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48960");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48961");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48962");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48967");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48968");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48969");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48970");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48971");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48972");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48973");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48975");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48977");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48978");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48981");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48985");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48987");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48988");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48991");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48992");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48994");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48995");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48997");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48999");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49000");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49002");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49003");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49005");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49006");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49007");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49010");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49011");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49012");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49014");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49015");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49016");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49019");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49021");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49022");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49023");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49024");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49025");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49026");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49027");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49028");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49029");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49031");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49032");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-2166");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-28327");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52766");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52800");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52881");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52919");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-6270");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27043");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42145");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43854");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-44947");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-45013");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-45016");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-45026");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46716");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46813");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46814");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46815");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46816");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46817");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46818");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46849");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47668");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47674");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47684");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47706");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47747");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47748");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49860");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49867");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49925");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49930");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49936");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49945");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49960");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49969");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49974");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49982");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49991");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49995");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50047");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50208");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-50047");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/12/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cluster-md-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dlm-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gfs2-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-64kb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-64kb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-livepatch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-livepatch-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-5_14_21-150400_24_141-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-obs-build");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-zfcpdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ocfs2-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:reiserfs-kmp-default");
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
if (isnull(os_release) || os_release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)(?:_SAP)?\d+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES15|SLES_SAP15)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15 / SLES_SAP15', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(4)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP4", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP15" && (! preg(pattern:"^(4)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP15 SP4", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'kernel-default-5.14.21-150400.24.141.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'kernel-default-base-5.14.21-150400.24.141.1.150400.24.68.2', 'sp':'4', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'kernel-default-devel-5.14.21-150400.24.141.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'kernel-devel-5.14.21-150400.24.141.1', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'kernel-macros-5.14.21-150400.24.141.1', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'kernel-obs-build-5.14.21-150400.24.141.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'kernel-source-5.14.21-150400.24.141.1', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'kernel-syms-5.14.21-150400.24.141.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'reiserfs-kmp-default-5.14.21-150400.24.141.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'kernel-64kb-5.14.21-150400.24.141.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'kernel-64kb-devel-5.14.21-150400.24.141.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'kernel-default-5.14.21-150400.24.141.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'kernel-default-5.14.21-150400.24.141.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4', 'SUSE-Manager-Proxy-release-4.3']},
    {'reference':'kernel-default-base-5.14.21-150400.24.141.1.150400.24.68.2', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'kernel-default-base-5.14.21-150400.24.141.1.150400.24.68.2', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3']},
    {'reference':'kernel-default-devel-5.14.21-150400.24.141.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'kernel-default-devel-5.14.21-150400.24.141.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4', 'SUSE-Manager-Proxy-release-4.3']},
    {'reference':'kernel-devel-5.14.21-150400.24.141.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3']},
    {'reference':'kernel-macros-5.14.21-150400.24.141.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3']},
    {'reference':'kernel-obs-build-5.14.21-150400.24.141.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'kernel-obs-build-5.14.21-150400.24.141.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'kernel-source-5.14.21-150400.24.141.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3']},
    {'reference':'kernel-syms-5.14.21-150400.24.141.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'kernel-syms-5.14.21-150400.24.141.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4', 'SUSE-Manager-Proxy-release-4.3']},
    {'reference':'reiserfs-kmp-default-5.14.21-150400.24.141.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'reiserfs-kmp-default-5.14.21-150400.24.141.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'kernel-64kb-5.14.21-150400.24.141.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4', 'sles-ltss-release-15.4']},
    {'reference':'kernel-64kb-devel-5.14.21-150400.24.141.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4', 'sles-ltss-release-15.4']},
    {'reference':'kernel-default-5.14.21-150400.24.141.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'kernel-default-5.14.21-150400.24.141.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'kernel-default-base-5.14.21-150400.24.141.1.150400.24.68.2', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4', 'sles-ltss-release-15.4']},
    {'reference':'kernel-default-base-5.14.21-150400.24.141.1.150400.24.68.2', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4', 'sles-ltss-release-15.4']},
    {'reference':'kernel-default-devel-5.14.21-150400.24.141.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'kernel-default-devel-5.14.21-150400.24.141.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'kernel-devel-5.14.21-150400.24.141.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4', 'sles-ltss-release-15.4']},
    {'reference':'kernel-macros-5.14.21-150400.24.141.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4', 'sles-ltss-release-15.4']},
    {'reference':'kernel-obs-build-5.14.21-150400.24.141.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'kernel-obs-build-5.14.21-150400.24.141.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'kernel-source-5.14.21-150400.24.141.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4', 'sles-ltss-release-15.4']},
    {'reference':'kernel-syms-5.14.21-150400.24.141.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'kernel-syms-5.14.21-150400.24.141.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'reiserfs-kmp-default-5.14.21-150400.24.141.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'reiserfs-kmp-default-5.14.21-150400.24.141.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'kernel-default-5.14.21-150400.24.141.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'kernel-default-devel-5.14.21-150400.24.141.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'kernel-syms-5.14.21-150400.24.141.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'kernel-zfcpdump-5.14.21-150400.24.141.1', 'sp':'4', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'cluster-md-kmp-default-5.14.21-150400.24.141.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.4']},
    {'reference':'dlm-kmp-default-5.14.21-150400.24.141.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.4']},
    {'reference':'gfs2-kmp-default-5.14.21-150400.24.141.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.4']},
    {'reference':'ocfs2-kmp-default-5.14.21-150400.24.141.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.4']},
    {'reference':'kernel-default-livepatch-5.14.21-150400.24.141.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.4']},
    {'reference':'kernel-default-livepatch-devel-5.14.21-150400.24.141.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.4']},
    {'reference':'kernel-livepatch-5_14_21-150400_24_141-default-1-150400.9.5.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.4']},
    {'reference':'kernel-default-5.14.21-150400.24.141.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.4']},
    {'reference':'kernel-default-devel-5.14.21-150400.24.141.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.4']},
    {'reference':'kernel-obs-build-5.14.21-150400.24.141.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.4']},
    {'reference':'kernel-syms-5.14.21-150400.24.141.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.4']},
    {'reference':'kernel-zfcpdump-5.14.21-150400.24.141.1', 'sp':'4', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.4']},
    {'reference':'reiserfs-kmp-default-5.14.21-150400.24.141.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.4']}
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
        if ('ltss' >< tolower(check)) ltss_caveat_required = TRUE;
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  var ltss_plugin_caveat = NULL;
  if(ltss_caveat_required) ltss_plugin_caveat = '\n' +
    'NOTE: This vulnerability check contains fixes that apply to\n' +
    'packages only available in SUSE Enterprise Linux Server LTSS\n' +
    'repositories. Access to these package security updates require\n' +
    'a paid SUSE LTSS subscription.\n';
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + ltss_plugin_caveat
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cluster-md-kmp-default / dlm-kmp-default / gfs2-kmp-default / etc');
}
