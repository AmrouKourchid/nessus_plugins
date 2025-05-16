#TRUSTED 764dc5c559599839cf76462ade249561d7662328102b1c25688624018c3830cc7278b49d07d3f645b08d41fec43bac3d3bd3e9a3fd6a9ce17c61c6fa09ef56ca491dd074c31dd030909fc97ee0c04bfc845559da66851c0c8cd274e69482acc2cb8f0992e1c63e3db349e0d6c5c6878bcd899b629c79b4948975675c41318ca567a8114556ecc0f06f1d4018e20a64a2b0ac1eb1b5cbfab9b8aa4b2f02aee89b3822c4e5983a7c82809cf4e2fe64f333c674bdb7d46a579efd39612de691819ebbc923a504e07d51090d6da3a73a09c1f67525ca969986183260e1bde506bc342a6c1716f281d4d86a477c17591a4a787918233aabf596a13341f4ac5f51c27d16375cab3dea4fc3c3f7500465d2ae554f9ab33f70bf4d24ba4d7a6103245ce1ca23ee480900c98d2d6fe147145ef209996697dec9451199101cf270eba29f101a5d1288f53e8b029230f486f98c9c4f9c961c175d0a7048c4c1082efe4723e2b3885c3c0c87089450ab685bd9578f14f04d994a30e36ad6fcdba74ec7abc7472f3e465d4b29cdb41db86606f9c1df27936ce12e077d799b9e8cb8f3be935ef3927860ac25f842e8b4c2dc21bec1b9ba7aa75d3e6816247a287d7b76f782640e2518d5fabd917d7fd34735e603afdcb8adb06490b5d1ff226a0972a34abb176a5196c9de0f7c69f81d3f5a2633b74188decf1f93eedbe0024b59544504d7caa6
#TRUST-RSA-SHA256 1bbcdd9cb6baafd186bb313ba8424d04b1b6ebe9d0b497537d513fa931a8ee0b2e03c46cca92e37abb00a1dbb99b545bdd3bb72a00210641a537b8eb74b64c17b5852f8b51b766ef3923a61ac7e07a3dc5df7bb7fcc3ea4fe531f7b958e0eece87e1bb8c3bb668d3383ce5534156ed5be45738cdc9d28f68ad7d692ff695343f8ab474321e964e58f89fc65b84211c67de4318250adbd5aae2f138d0c7abbb98edfde293a1a22ea5f693f2ad4e3b5339679bda98eed2dfa9a4a01164d6eb3acb62d4ed3607a64c3f81a66d1bcb1610ef4edf156499cbc711d279654a46af2bd739192c545ba5e7a4e1633b4b264843de77ab3540e7a699e01c09f166c3faa6e236f43f6667a8bb4360465d0c765e51b72ab1425de525ed42f5e229e63e488ad75f3a7802fe12e7d623dd29fd82f4ec449611d0b14b5d406919ddd2bc2682480bb242e0aa5671954ce1d1ec48736f206a01c9cd8848860fe1f7628473f1c1621a8e530a5f33672e172dcdc88ee097152c46e3ebac88ccbea27544304699f5cf659ca60edc9c723264e8a348c81ae5046334f9d6c138fedf163d62c10a728c541198883786e95c6fa6abfc8e1d49afe0c759ac33c46307e5fbe0e8ffdce464721bfd85b9d19bff3a9e651f35e3d3db52a9fb1a4ad82d813ddb35fb4e9960f489c338327d9a9e93660aba7429126d738d49a5f36ead720d902556334c6cb4f4bc46
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(189763);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/26");

  script_cve_id("CVE-2024-21596");
  script_xref(name:"JSA", value:"JSA75735");

  script_name(english:"Juniper Junos OS Vulnerability (JSA75735)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA75735
advisory.

  - A Heap-based Buffer Overflow vulnerability in the Routing Protocol Daemon (RPD) of Juniper Networks Junos
    OS and Junos OS Evolved allows an unauthenticated, network based attacker to cause a Denial of Service
    (DoS). If an attacker sends a specific BGP UPDATE message to the device, this will cause a memory
    overwrite and therefore an RPD crash and restart in the backup Routing Engine (RE). Continued receipt of
    these packets will cause a sustained Denial of Service (DoS) condition in the backup RE. The primary RE is
    not impacted by this issue and there is no impact on traffic. This issue only affects devices with NSR
    enabled. This issue requires an attacker to have an established BGP session to a system affected by the
    issue. This issue affects both eBGP and iBGP implementations. This issue affects: Juniper Networks Junos
    OS * All versions earlier than 20.4R3-S9; * 21.2 versions earlier than 21.2R3-S7; * 21.3 versions earlier
    than 21.3R3-S5; * 21.4 versions earlier than 21.4R3-S5; * 22.1 versions earlier than 22.1R3-S4; * 22.2
    versions earlier than 22.2R3-S2; * 22.3 versions earlier than 22.3R3-S1; * 22.4 versions earlier than
    22.4R2-S2, 22.4R3; * 23.1 versions earlier than 23.1R2; * 23.2 versions earlier than 23.2R1-S2, 23.2R2.
    Juniper Networks Junos OS Evolved * All versions earlier than 21.3R3-S5-EVO; * 21.4-EVO versions earlier
    than 21.4R3-S5-EVO; * 22.1-EVO versions earlier than 22.1R3-S4-EVO; * 22.2-EVO versions earlier than
    22.2R3-S2-EVO; * 22.3-EVO versions later than 22.3R1-EVO; * 22.4-EVO versions earlier than 22.4R2-S2-EVO,
    22.4R3-EVO; * 23.1-EVO versions earlier than 23.1R2-EVO; * 23.2-EVO versions earlier than 23.2R1-S2-EVO,
    23.2R2-EVO. (CVE-2024-21596)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://supportportal.juniper.net/s/article/Overview-of-the-Juniper-Networks-SIRT-Quarterly-Security-Bulletin-Publication-Process?r=40&ui-knowledge-components-aura-actions.KnowledgeArticleVersionCreateDraftFromOnlineAction.createDraftFromOnlineArticle=1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f52ed971");
  # https://supportportal.juniper.net/s/article/In-which-releases-are-vulnerabilities-fixed?r=40&ui-knowledge-components-aura-actions.KnowledgeArticleVersionCreateDraftFromOnlineAction.createDraftFromOnlineArticle=1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f121aca9");
  # https://supportportal.juniper.net/s/article/Common-Vulnerability-Scoring-System-CVSS-and-Juniper-s-Security-Advisories?r=40&ui-knowledge-components-aura-actions.KnowledgeArticleVersionCreateDraftFromOnlineAction.createDraftFromOnlineArticle=1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a73cfa7d");
  # https://supportportal.juniper.net/s/article/2024-01-Security-Bulletin-Junos-OS-and-Junos-OS-Evolved-A-specific-BGP-UPDATE-message-will-cause-a-crash-in-the-backup-Routing-Engine-CVE-2024-21596
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0ba27a10");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA75735");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-21596");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/01/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/30");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include('junos.inc');
include('junos_kb_cmd_func.inc');

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'0.0', 'fixed_ver':'20.4R3-S9'},
  {'min_ver':'0.0-EVO', 'fixed_ver':'21.3R3-S5-EVO'},
  {'min_ver':'21.2', 'fixed_ver':'21.2R3-S7'},
  {'min_ver':'21.3', 'fixed_ver':'21.3R3-S5'},
  {'min_ver':'21.4', 'fixed_ver':'21.4R3-S5'},
  {'min_ver':'21.4-EVO', 'fixed_ver':'21.4R3-S5-EVO'},
  {'min_ver':'22.1', 'fixed_ver':'22.1R3-S4'},
  {'min_ver':'22.1-EVO', 'fixed_ver':'22.1R3-S4-EVO'},
  {'min_ver':'22.2', 'fixed_ver':'22.2R3-S2'},
  {'min_ver':'22.2-EVO', 'fixed_ver':'22.2R3-S2-EVO'},
  {'min_ver':'22.3', 'fixed_ver':'22.3R3-S1'},
  {'min_ver':'22.3-EVO', 'fixed_ver':'22.3R1-EVO'},
  {'min_ver':'22.4', 'fixed_ver':'22.4R2-S2', 'fixed_display':'22.4R2-S2, 22.4R3'},
  {'min_ver':'22.4-EVO', 'fixed_ver':'22.4R2-S2-EVO', 'fixed_display':'22.4R2-S2-EVO, 22.4R3-EVO'},
  {'min_ver':'23.2', 'fixed_ver':'23.2R1-S2', 'fixed_display':'23.2R1-S2, 23.2R2'},
  {'min_ver':'23.2-EVO', 'fixed_ver':'23.2R1-S2-EVO', 'fixed_display':'23.2R1-S2-EVO, 23.2R2-EVO'}
];

var override = TRUE;
var buf = junos_command_kb_item(cmd:'show configuration | display set');
if (buf)
{
  override = FALSE;
  if (!preg(string:buf, pattern:"^set protocols bgp", multiline:TRUE))
    audit(AUDIT_HOST_NOT, 'using a vulnerable configuration');
  if (!preg(string:buf, pattern:"^set routing-options nonstop-routing", multiline:TRUE))
    audit(AUDIT_HOST_NOT, 'affected because the Nonstop Active Routing (NSR) feature is not enabled');
}

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);
