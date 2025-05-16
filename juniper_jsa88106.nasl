#TRUSTED 1a4118bcf580dec3717ca8cccc3c68a40d02d52a934101a074da2b72d52f1ffcc38023e57225698ed19928124dec6f8168b6fc187746d5a5e1ada77787b5135a69eee094b9568862971bea88c719848efa86bc65e283959acdfe8b6757c4deb5baa6fb0d4e854eb8ffc117d935f0f1948b4421b177773bff367236ef94eacde2971de4557d09b51e53631742ae5602a9bb6a89afc21a329a82a472c44137a47f6168f7d7c924dff2caadb75092090314d8c5f0c6c9cc614d54a271d78518605465f67a5acfbf06cbafe11b7bbe82d87084102166bced3d7707d4ae176284de8729dd6e3fdfb05cb0453d16643cd5b49efcf823d64541d5b81a37a0d374583dc6a54d83845bda55d4c49da043a17d951c538810ac5af812a0c1bb936fefc9348d80aa56ca42ff79965c7543254310998d9433fd864556617096669db2b3e8fcb2bd31974f7fb8aac33e93d6fbedae5d1a067c54f02ef5a76004ef60b057c5ea139ede36bb15a524dc2c856f993199c7ee1a36fb3c2793a63bf9bdec392b1c1be8b9bca971d72dea05d374130af024c91a5aac35ce64b4a4ce82043cdd1a33c906614935f925ca263fe756ec4910014fe46fe81692bdcfcc66b46f645e704bc342b546e44ee6142d796d83e9661dfa90a310a5510fd6e89c49fe918a027e8f0a9c5773f272fe550e01c7e0c4004136f77de807c9391fd2cd9bfdb352b5ee51b996
#TRUST-RSA-SHA256 4ed375bbbdec2121a6f3910fedde94e40112703ef1d885161577020bf08c895ef7b0c84a9268a3fbb8f8d3becf1e69d2f3c04ca4d11cf7436593a8996f974f2f58f26938550d5979cfa2b106aff550b70cb5970e7e2afaf576fdb7a791fbdf0524b6dc23ca912289976e60688e183c09d5105c9dcfcdabd5c71042275a18726bd09a184103cfe06df93b93cf5bc9df50ff8cbb39febc4042509a1dcc7d92fbbb32189c930c668b15ed1d7b6739ce1b6a4320d9a6a1db4194b10ef988c40c9aa8c76911815d23c4ba7e58264b4d893f953ba2fcce19cf9393b14841c04338bd70dd9a24ec3b30859deba7229f20d081de692e98ceea70adf0eefe273a67f89a7242bc8d0b40842d2e82c0dadd9730e4ed9d3457f0a1ad2583e4f1f72da61ff42573172228c436a399e31968de5fe7ce5ebc111371526d9eaafd961d9078f44ea8555994d7dd367da330ea9b3054483269903a812418bad59c0aae29e8613bd98b426cf6b3ad3c02aee1f63c106c4bdd863a0e5e9d7530da8b4a1cfe866cbd10854a23f986ae27c9c5c062694a8600b6165f633244f1ef2f3ab60a97609a255b761e8bb71fb9d8370f95685f001e0941e3a7d804dd91fed26c54dd355c25e7f4eb29f93251104536fe523d3c3e94f1a25266902eb35ead58ebafa11a566db8f0f745ba6d52a73baf42818f7199b612aa33e876b3cdbe0c37f23a0a496188ec1742
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(210491);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/07");

  script_cve_id("CVE-2024-39544");
  script_xref(name:"JSA", value:"JSA88106");
  script_xref(name:"IAVA", value:"2024-A-0650");

  script_name(english:"Juniper Junos OS Vulnerability (JSA88106)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA88106
advisory.

  - An Incorrect Default Permissions vulnerability in the command line interface (CLI) of Juniper Networks
    Junos OS Evolved allows a low privileged local attacker to view NETCONF traceoptions files, representing
    an exposure of sensitive information. (CVE-2024-39544)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://supportportal.juniper.net/s/article/2024-10-Security-Bulletin-Junos-OS-Evolved-Low-privileged-local-user-able-to-view-NETCONF-traceoptions-files-CVE-2024-39544
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6ed78a71");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA88106");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-39544");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/07");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
  {'min_ver':'0.0-EVO', 'fixed_ver':'20.4R3-S9-EVO'},
  {'min_ver':'21.2-EVO', 'fixed_ver':'21.2R3-S7-EVO'},
  {'min_ver':'21.4-EVO', 'fixed_ver':'21.4R3-S5-EVO'},
  {'min_ver':'22.1-EVO', 'fixed_ver':'22.1R3-S5-EVO'},
  {'min_ver':'22.2-EVO', 'fixed_ver':'22.2R3-S3-EVO'},
  {'min_ver':'22.3-EVO', 'fixed_ver':'22.3R3-EVO', 'fixed_display':'22.3R3-EVO, 22.3R3-S2-EVO'},
  {'min_ver':'22.4-EVO', 'fixed_ver':'22.4R3-EVO'},
  {'min_ver':'23.2-EVO', 'fixed_ver':'23.2R1-S2-EVO', 'fixed_display':'23.2R1-S2-EVO, 23.2R2-EVO'}
];

var override = TRUE;
var buf = junos_command_kb_item(cmd:'show configuration | display set');
if (buf)
{
  override = FALSE;
  if (!junos_check_config(buf:buf, pattern:"^set system services netconf traceoptions"))
    audit(AUDIT_HOST_NOT, 'using a vulnerable configuration');
}

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);
