#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2024:0857-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(192014);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/16");

  script_cve_id(
    "CVE-2019-25162",
    "CVE-2020-36777",
    "CVE-2020-36784",
    "CVE-2021-46904",
    "CVE-2021-46905",
    "CVE-2021-46906",
    "CVE-2021-46915",
    "CVE-2021-46924",
    "CVE-2021-46929",
    "CVE-2021-46932",
    "CVE-2021-46934",
    "CVE-2021-46953",
    "CVE-2021-46964",
    "CVE-2021-46966",
    "CVE-2021-46968",
    "CVE-2021-46974",
    "CVE-2021-46989",
    "CVE-2021-47005",
    "CVE-2021-47012",
    "CVE-2021-47013",
    "CVE-2021-47054",
    "CVE-2021-47060",
    "CVE-2021-47061",
    "CVE-2021-47069",
    "CVE-2021-47076",
    "CVE-2021-47078",
    "CVE-2021-47083",
    "CVE-2022-20154",
    "CVE-2022-48627",
    "CVE-2023-6817",
    "CVE-2023-28746",
    "CVE-2023-35827",
    "CVE-2023-46343",
    "CVE-2023-51042",
    "CVE-2023-52340",
    "CVE-2023-52429",
    "CVE-2023-52439",
    "CVE-2023-52443",
    "CVE-2023-52445",
    "CVE-2023-52448",
    "CVE-2023-52449",
    "CVE-2023-52451",
    "CVE-2023-52463",
    "CVE-2023-52475",
    "CVE-2023-52478",
    "CVE-2023-52482",
    "CVE-2023-52502",
    "CVE-2023-52530",
    "CVE-2023-52531",
    "CVE-2023-52532",
    "CVE-2023-52569",
    "CVE-2023-52574",
    "CVE-2023-52597",
    "CVE-2023-52605",
    "CVE-2024-0340",
    "CVE-2024-0607",
    "CVE-2024-1151",
    "CVE-2024-23849",
    "CVE-2024-23851",
    "CVE-2024-26585",
    "CVE-2024-26586",
    "CVE-2024-26589",
    "CVE-2024-26593",
    "CVE-2024-26595",
    "CVE-2024-26602",
    "CVE-2024-26607",
    "CVE-2024-26622"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2024:0857-1");

  script_name(english:"SUSE SLES15 Security Update : kernel (SUSE-SU-2024:0857-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 / SLES_SAP15 host has packages installed that are affected by multiple vulnerabilities as
referenced in the SUSE-SU-2024:0857-1 advisory.

    The SUSE Linux Enterprise 15 SP3 kernel was updated to receive various security bugfixes.

    The following security bugs were fixed:

    - CVE-2023-28746: Fixed Register File Data Sampling (bsc#1213456).
    - CVE-2023-52502: Fixed a race condition in nfc_llcp_sock_get() and nfc_llcp_sock_get_sn() (bsc#1220831).
    - CVE-2024-26589: Fixed out of bounds read due to variable offset alu on PTR_TO_FLOW_KEYS (bsc#1220255).
    - CVE-2024-26585: Fixed race between tx work scheduling and socket close  (bsc#1220187).
    - CVE-2023-52340: Fixed ICMPv6 Packet Too Big packets force a DoS of the Linux kernel by forcing
    100% CPU (bsc#1219295).
    - CVE-2024-0607: Fixed 64-bit load issue in  nft_byteorder_eval() (bsc#1218915).
    - CVE-2023-6817: Fixed use-after-free in nft_pipapo_walk (bsc#1218195).
    - CVE-2024-26622: Fixed UAF write bug in tomoyo_write_control() (bsc#1220825).
    - CVE-2023-52451: Fixed access beyond end of drmem array  (bsc#1220250).
    - CVE-2021-46932: Fixed missing work initialization before device registration (bsc#1220444)
    - CVE-2023-52463: Fixed null pointer dereference in efivarfs (bsc#1220328).
    - CVE-2023-52449: Fixed gluebi NULL pointer dereference caused by ftl notifier  (bsc#1220238).
    - CVE-2023-52475: Fixed use-after-free in powermate_config_complete (bsc#1220649)
    - CVE-2023-52478: Fixed kernel crash on receiver USB disconnect (bsc#1220796)
    - CVE-2021-46915: Fixed a bug to avoid possible divide error in nft_limit_init (bsc#1220436).
    - CVE-2021-46924: Fixed fix memory leak in device probe and remove (bsc#1220459)
    - CVE-2019-25162: Fixed a potential use after free (bsc#1220409).
    - CVE-2020-36784: Fixed reference leak when pm_runtime_get_sync fails (bsc#1220570).
    - CVE-2023-52445: Fixed use after free on context disconnection (bsc#1220241).
    - CVE-2023-46343: Fixed a NULL pointer dereference in send_acknowledge() (CVE-2023-46343).
    - CVE-2023-52439: Fixed use-after-free in uio_open (bsc#1220140).
    - CVE-2023-52443: Fixed crash when parsed profile name is empty  (bsc#1220240).
    - CVE-2024-26602: Fixed overall slowdowns with sys_membarrier (bsc1220398).
    - CVE-2024-26593: Fixed block process call transactions (bsc#1220009).
    - CVE-2021-47013: Fixed a use after free in emac_mac_tx_buf_send (bsc#1220641).
    - CVE-2024-26586: Fixed stack corruption (bsc#1220243).
    - CVE-2024-26595: Fixed NULL pointer dereference in  error path (bsc#1220344).
    - CVE-2023-52448: Fixed kernel NULL pointer dereference in gfs2_rgrp_dump  (bsc#1220253).
    - CVE-2024-1151: Fixed unlimited number of recursions from action  sets (bsc#1219835).
    - CVE-2024-23849: Fixed array-index-out-of-bounds in rds_cmsg_recv  (bsc#1219127).
    - CVE-2024-0340: Fixed information disclosure in vhost/vhost.c:vhost_new_msg() (bsc#1218689).
    - CVE-2023-51042: Fixed use-after-free in amdgpu_cs_wait_all_fences in
    drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c (bsc#1219128).
    - CVE-2021-47078: Fixed a bug by clearing all QP fields if creation failed (bsc#1220863)
    - CVE-2021-47076: Fixed a bug by returning CQE error if invalid lkey was supplied (bsc#1220860)
    - CVE-2023-52605: Fixed a NULL pointer dereference check (bsc#1221039)
    - CVE-2023-52569: Fixed a bug in btrfs by remoning BUG() after failure to insert delayed dir index item
    (bsc#1220918).
    - CVE-2023-52482: Fixex a bug by adding SRSO mitigation for Hygon processors (bsc#1220735).
    - CVE-2023-52597: Fixed a setting of fpc register in KVM (bsc#1221040).
    - CVE-2022-48627: Fixed a memory overlapping when deleting chars in the buffer (bsc#1220845).
    - CVE-2023-52574: Fixed a bug by hiding new member header_ops (bsc#1220870).
    - CVE-2021-46934: Fixed a bug by validating user data in compat ioctl (bsc#1220469).
    - CVE-2023-35827: Fixed a use-after-free issue in ravb_tx_timeout_work() (bsc#1212514).
    - CVE-2023-52532: Fixed a bug in TX CQE error handling (bsc#1220932).
    - CVE-2023-52530: Fixed a potential key use-after-free in wifi mac80211 (bsc#1220930).
    - CVE-2023-52531: Fixed a memory corruption issue in iwlwifi (bsc#1220931).
    - CVE-2021-47083: Fixed a global-out-of-bounds issue in mediatek: (bsc#1220917).
    - CVE-2024-26607: Fixed a probing race issue in sii902x: (bsc#1220736).
    - CVE-2021-47005: Fixed a NULL pointer dereference for ->get_features() (bsc#1220660).
    - CVE-2021-47060: Fixed a bug in KVM by stop looking for coalesced MMIO zones if the bus is destroyed
    (bsc#1220742).
    - CVE-2021-47012: Fixed a use after free in siw_alloc_mr (bsc#1220627).
    - CVE-2021-46989: Fixed a bug by preventing corruption in shrinking truncate in hfsplus (bsc#1220737).
    - CVE-2021-47061: Fixed a bug in KVM by destroy I/O bus devices on unregister failure _after_  sync'ing
    SRCU (bsc#1220745).


Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200599");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207653");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212514");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213456");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1216223");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218195");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218689");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218915");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219127");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219128");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219146");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219295");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219653");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219827");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219835");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219915");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220009");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220140");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220187");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220238");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220240");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220241");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220243");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220250");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220253");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220255");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220328");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220330");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220344");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220398");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220409");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220416");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220418");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220421");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220436");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220444");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220459");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220469");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220482");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220526");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220538");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220570");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220572");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220599");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220627");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220641");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220649");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220660");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220689");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220700");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220735");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220736");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220737");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220742");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220745");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220767");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220796");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220825");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220826");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220831");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220845");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220860");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220863");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220870");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220917");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220918");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220930");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220931");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220932");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221039");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221040");
  # https://lists.suse.com/pipermail/sle-security-updates/2024-March/018154.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fa461192");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-25162");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-36777");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-36784");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46904");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46905");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46906");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46915");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46924");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46929");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46932");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46934");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46953");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46964");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46966");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46968");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46974");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46989");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47005");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47012");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47013");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47054");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47060");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47061");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47069");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47076");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47078");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47083");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-20154");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48627");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-28746");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-35827");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-46343");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-51042");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52340");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52429");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52439");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52443");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52445");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52448");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52449");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52451");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52463");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52475");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52478");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52482");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52502");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52530");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52531");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52532");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52569");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52574");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52597");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52605");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-6817");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-0340");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-0607");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-1151");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-23849");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-23851");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26585");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26586");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26589");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26593");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26595");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26602");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26607");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26622");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20154");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-26622");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/06/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/03/13");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-5_3_18-150300_59_153-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-obs-build");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-preempt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-preempt-devel");
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
if (os_ver == "SLES15" && (! preg(pattern:"^(3)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP3", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP15" && (! preg(pattern:"^(3)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP15 SP3", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'kernel-default-5.3.18-150300.59.153.2', 'sp':'3', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'kernel-default-base-5.3.18-150300.59.153.2.150300.18.90.2', 'sp':'3', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'kernel-default-devel-5.3.18-150300.59.153.2', 'sp':'3', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'kernel-devel-5.3.18-150300.59.153.2', 'sp':'3', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'kernel-macros-5.3.18-150300.59.153.2', 'sp':'3', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'kernel-obs-build-5.3.18-150300.59.153.2', 'sp':'3', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'kernel-preempt-5.3.18-150300.59.153.2', 'sp':'3', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'kernel-preempt-devel-5.3.18-150300.59.153.2', 'sp':'3', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'kernel-source-5.3.18-150300.59.153.2', 'sp':'3', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'kernel-syms-5.3.18-150300.59.153.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'reiserfs-kmp-default-5.3.18-150300.59.153.2', 'sp':'3', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'kernel-64kb-5.3.18-150300.59.153.2', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3', 'sles-ltss-release-15.3']},
    {'reference':'kernel-64kb-devel-5.3.18-150300.59.153.2', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3', 'sles-ltss-release-15.3']},
    {'reference':'kernel-default-5.3.18-150300.59.153.2', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'kernel-default-5.3.18-150300.59.153.2', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'kernel-default-base-5.3.18-150300.59.153.2.150300.18.90.2', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'kernel-default-base-5.3.18-150300.59.153.2.150300.18.90.2', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'kernel-default-devel-5.3.18-150300.59.153.2', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'kernel-default-devel-5.3.18-150300.59.153.2', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'kernel-devel-5.3.18-150300.59.153.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3', 'sles-ltss-release-15.3']},
    {'reference':'kernel-macros-5.3.18-150300.59.153.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3', 'sles-ltss-release-15.3']},
    {'reference':'kernel-obs-build-5.3.18-150300.59.153.2', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'kernel-obs-build-5.3.18-150300.59.153.2', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'kernel-preempt-5.3.18-150300.59.153.2', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3', 'sles-ltss-release-15.3']},
    {'reference':'kernel-preempt-5.3.18-150300.59.153.2', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3', 'sles-ltss-release-15.3']},
    {'reference':'kernel-preempt-devel-5.3.18-150300.59.153.2', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3', 'sles-ltss-release-15.3']},
    {'reference':'kernel-preempt-devel-5.3.18-150300.59.153.2', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3', 'sles-ltss-release-15.3']},
    {'reference':'kernel-source-5.3.18-150300.59.153.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3', 'sles-ltss-release-15.3']},
    {'reference':'kernel-syms-5.3.18-150300.59.153.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'kernel-syms-5.3.18-150300.59.153.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'reiserfs-kmp-default-5.3.18-150300.59.153.2', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'reiserfs-kmp-default-5.3.18-150300.59.153.2', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'cluster-md-kmp-default-5.3.18-150300.59.153.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.3']},
    {'reference':'dlm-kmp-default-5.3.18-150300.59.153.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.3']},
    {'reference':'gfs2-kmp-default-5.3.18-150300.59.153.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.3']},
    {'reference':'ocfs2-kmp-default-5.3.18-150300.59.153.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.3']},
    {'reference':'kernel-default-livepatch-5.3.18-150300.59.153.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.3']},
    {'reference':'kernel-default-livepatch-devel-5.3.18-150300.59.153.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.3']},
    {'reference':'kernel-livepatch-5_3_18-150300_59_153-default-1-150300.7.3.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.3']},
    {'reference':'kernel-default-5.3.18-150300.59.153.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.3']},
    {'reference':'kernel-default-base-5.3.18-150300.59.153.2.150300.18.90.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.3']},
    {'reference':'kernel-default-devel-5.3.18-150300.59.153.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.3']},
    {'reference':'kernel-obs-build-5.3.18-150300.59.153.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.3']},
    {'reference':'kernel-syms-5.3.18-150300.59.153.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.3']},
    {'reference':'kernel-zfcpdump-5.3.18-150300.59.153.2', 'sp':'3', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.3']},
    {'reference':'reiserfs-kmp-default-5.3.18-150300.59.153.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.3']}
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
