#TRUSTED 239fa9c68d699572672bce624abb9f58974a63e85a488c01886605f89921332ad1762e43e439c52d0bff398e353e7ff276576e6eca4eb12c86426b260f9c031ee7f54d438c69f81616498b2e269f4eef330adae0f464c89bfcdda8eacac5bfe03bac1171c9e8f07f329188d8dc0497b72a59d6a2d97bf7be79124f280cbf130cb178b46854abbb39207afed4d9eeee2a33741b961240f375b7049285b1b9eee461d5afefc6a9b005c08244793e137ad3cbaed43da34e902194ff23cd76cce13f0ea013f36d0c24f3ca03f93fb47d406617374109e6bb0da8ff435187760365eb9726c8a2ebf021cff19322beff67b443c104413f89287dce8f5a66619d16c3378153452efcbfe57f2c2844517ddfba47353aeee9e8364d8386181ccf4e387f491b084b40e74ac4c17e71e41eb3f59f2db1297eda24c7adf485c7d347e12cdd3de84fb9c9615e225f81f84615b111421b7a4e236be988756c066e4e0758b3997b7229025e7351a9c590a6db67e2ab68bd1d23543b05190d4d2b671c3fd0c4270ec372d3896a068daadfe1fc1ff34177f14371b37234ae07b5fadf742da5f06276978081e99c20d1d156909ac29ddcc7c460d3d78532fd63e08e2e1c4721b6b6120737adc6842cd92ef17c32883cab11465c9cf3f04a312dcae0d03e137ee1801efc99b5403691e584c8b908058bba8d5ce19cba7decfa4db3169beb0d33d31583
#TRUST-RSA-SHA256 6f20949370c4e6278947ad471bfd9d3c00ccd187e6e74b4b4bc78d494ef9a90652825a9824e52415aba97ddf0c5535ce9fa1d55db5e7148e5d520c0b2c069bf51f5ccd4bdf68d17f62fab6c92118b85741a06e2be19a306610908dba4ff61d4cced6ce2e8750e8b5c820c86aace0a17c4c4c7ff9e5376b245c49106de16c88c30c67e18672e7f0b9269e5e803cd6152f1c1a7ebe96d7b76ccff0b4a14f77820a4ba86cab42fba167a5505960f961f26e46351d009a0a887576956360318962670eb90caf2d453ea6bd7b7d7456098fa2cd25f1dad7676bc48aef45cdb621ea6756171723918af0148165c43a7064c9142d14a6a7075815b4a9225b2f0fe338152f9af0087bff3eb2bdb0d3fe19f92970c2905a17bbdf8401df8e1b0e43df49a5e7c4bc8cb5f84b8df7bce4bdc14d7a933643afaeefacedc897e80d7bb70a669768f1d694d03d0377dfc1dbbbf854fc9853a9d3653fac014d1d567d35dbbad4d31dd363ff9cc5614ca0f2cfa2eca3c48f1d89c935ea9c1333650600e7cca882da23612e371fe006720b2ca8ea01061deaed76c01dfb7d5e4f66d781750629ec04493a90c98cdc2fccd3e35041f57fb438fcc4ce02a7791b2b5278975a369e96caa87c9236944c78b262a9379c50f27c0a413d86164d3a6fbb16cae9a9ab4738f7190bc03e929efe0d5a30353347ba45e556fbdaa90611fc6282cc41e1883ce61f
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(189740);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/26");

  script_cve_id("CVE-2024-21585");
  script_xref(name:"JSA", value:"JSA75723");

  script_name(english:"Juniper Junos OS Vulnerability (JSA75723)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA75723
advisory.

  - An Improper Handling of Exceptional Conditions vulnerability in BGP session processing of Juniper Networks
    Junos OS and Junos OS Evolved allows an unauthenticated network-based attacker, using specific timing
    outside the attacker's control, to flap BGP sessions and cause the routing protocol daemon (rpd) process
    to crash and restart, leading to a Denial of Service (DoS) condition. Continued BGP session flapping will
    create a sustained Denial of Service (DoS) condition. This issue only affects routers configured with non-
    stop routing (NSR) enabled. Graceful Restart (GR) helper mode, enabled by default, is also required for
    this issue to be exploitable. Note: NSR is not supported on the SRX Series and is therefore not affected
    by this vulnerability. When the BGP session flaps on the NSR-enabled router, the device enters GR-
    helper/LLGR-helper mode due to the peer having negotiated GR/LLGR-restarter capability and the backup BGP
    requests for replication of the GR/LLGR-helper session, master BGP schedules, and initiates replication of
    GR/LLGR stale routes to the backup BGP. In this state, if the BGP session with the BGP peer comes up
    again, unsolicited replication is initiated for the peer without cleaning up the ongoing GR/LLGR-helper
    mode replication. This parallel two instances of replication for the same peer leads to the assert if the
    BGP session flaps again. This issue affects: Juniper Networks Junos OS * All versions earlier than
    20.4R3-S9; * 21.2 versions earlier than 21.2R3-S7; * 21.3 versions earlier than 21.3R3-S5; * 21.4 versions
    earlier than 21.4R3-S5; * 22.1 versions earlier than 22.1R3-S4; * 22.2 versions earlier than 22.2R3-S3; *
    22.3 versions earlier than 22.3R3-S1; * 22.4 versions earlier than 22.4R2-S2, 22.4R3; * 23.2 versions
    earlier than 23.2R1-S1, 23.2R2. Juniper Networks Junos OS Evolved * All versions earlier than
    21.3R3-S5-EVO; * 21.4 versions earlier than 21.4R3-S5-EVO; * 22.1 versions earlier than 22.1R3-S4-EVO; *
    22.2 versions earlier than 22.2R3-S3-EVO; * 22.3 versions earlier than 22.3R3-S1-EVO; * 22.4 versions
    earlier than 22.4R2-S2-EVO, 22.4R3-EVO; * 23.2 versions earlier than 23.2R1-S1-EVO, 23.2R2-EVO.
    (CVE-2024-21585)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://supportportal.juniper.net/s/article/Overview-of-the-Juniper-Networks-SIRT-Quarterly-Security-Bulletin-Publication-Process?r=48&ui-knowledge-components-aura-actions.KnowledgeArticleVersionCreateDraftFromOnlineAction.createDraftFromOnlineArticle=1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b7b42de6");
  # https://supportportal.juniper.net/s/article/In-which-releases-are-vulnerabilities-fixed?r=48&ui-knowledge-components-aura-actions.KnowledgeArticleVersionCreateDraftFromOnlineAction.createDraftFromOnlineArticle=1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a955bc93");
  # https://supportportal.juniper.net/s/article/Common-Vulnerability-Scoring-System-CVSS-and-Juniper-s-Security-Advisories?r=48&ui-knowledge-components-aura-actions.KnowledgeArticleVersionCreateDraftFromOnlineAction.createDraftFromOnlineArticle=1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e61f1a02");
  # https://supportportal.juniper.net/s/article/MX-GR-and-LLGR-capability-and-compatibility-changes-after-15-1-release
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?aca53db1");
  # https://supportportal.juniper.net/s/article/2024-01-Security-Bulletin-Junos-OS-and-Junos-OS-Evolved-rpd-process-crash-due-to-BGP-flap-on-NSR-enabled-devices-CVE-2024-21585
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?892978d8");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA75723");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-21585");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/01/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/29");

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
  {'min_ver':'22.2', 'fixed_ver':'22.2R3-S3'},
  {'min_ver':'22.2-EVO', 'fixed_ver':'22.2R3-S3-EVO'},
  {'min_ver':'22.3', 'fixed_ver':'22.3R3-S1'},
  {'min_ver':'22.3-EVO', 'fixed_ver':'22.3R3-S1-EVO'},
  {'min_ver':'22.4', 'fixed_ver':'22.4R2-S2', 'fixed_display':'22.4R2-S2, 22.4R3'},
  {'min_ver':'22.4-EVO', 'fixed_ver':'22.4R2-S2-EVO', 'fixed_display':'22.4R2-S2-EVO, 22.4R3-EVO'},
  {'min_ver':'23.2', 'fixed_ver':'23.2R1-S1', 'fixed_display':'23.2R1-S1, 23.2R2'},
  {'min_ver':'23.2-EVO', 'fixed_ver':'23.2R1-S1-EVO', 'fixed_display':'23.2R1-S1-EVO, 23.2R2-EVO'}
];

var override = TRUE;
var buf = junos_command_kb_item(cmd:'show configuration | display set');
if (buf)
{
  override = FALSE;
  if (!preg(string:buf, pattern:"^set routing-options graceful-restart", multiline:TRUE))
    audit(AUDIT_HOST_NOT, 'affected because the Graceful Restart (GR) feature is not enabled');
  if (!preg(string:buf, pattern:"^set chassis redundancy graceful-switchover", multiline:TRUE))
    audit(AUDIT_HOST_NOT, 'affected because the Graceful Routing Engine Switchover (GRES) feature is not enabled');
  if (!preg(string:buf, pattern:"^set routing-options nonstop-routing", multiline:TRUE))
    audit(AUDIT_HOST_NOT, 'affected because the Nonstop Active Routing (NSR) feature is not enabled');
}

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);
