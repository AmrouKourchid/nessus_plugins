#TRUSTED 365da4915d7f298afe81b8cfcd9b213b74aa940601ebc27113ddf2877e747e85798212a4e6ff413f1998b124e1798d714d89f9da073a27a71ead02123c9232c411ee6e5ca65ef7b95ebe88bfbb3f7ab7dc6ab7b931eefb3fc8047fa1b0f60b40e1493d2309ddc006ba2564ca4d65a8290252ba6b9d6b8b6cf0bf55fcb4c3b59ce0d153a49b30657b8663b9619720b3f2b7ba2fc355f9e9f78152aa47a1f0330714d6735726866fc12fc8dd928a700b4226e37c36fdf5dc299c7df15ab5e2a818e5847e54f6e26455008a469e4e6c08f2bfe5cabc1592b6714206ee018785aa96af293ea52b00424649d61c54daa9671e5145a0e43fb02c7055f128df55163bb491c58d1a79ef32d926662c1c80506550946fa7cde42a0514beee8707ffd8620d6c6f4770ed20e4d10262a575edd58ab857e5edabd5398e2f173aa54a0ad29470256bbb4b65a1eb1f67d29eefe15dfdbede520202ae426e3044f9893e2cc8e78c7a7d6c1d87e76fe767f3d9cf6b346b5ab4f5e8c0f7433525390865d1d39e96c1d5b5fa8da8a6245e55777b2532c4b928b3a123d4eefb39619d642e9feba4081d65d056836f3564445968ae4aa6a2175a667e5a3901a689daf0fc2f45be010888df96b725d55ef190f93bb845240da64b9f57f4106799a643980645232fa2ec4a4c498d9b684ed06fe4a576851619f52a437377ca8097277f4a121d420c758c35
#TRUST-RSA-SHA256 64c83d997c00b778ac7fd2d9f0c28e6660737d9e70de160f52bb6df303b7765b8bbcd7015107469892b362ac222b8255b8559a7600a86f22dcd82845b86bf04c196b3f58f96400ba5b65223b6753bd1b245fe285fcd2870aa27fb88f73d792690ce6cb700f098a4b96169cb0982eee3373f316924384ab5b368cd750dc98d3a21803a3b8f0eaea62ce1f0b997022ee8606f9a9a5569899b7df95c87ba00030ce0718fbd3349c2e51999a358981f7bca4f9ae3df38800cbef97d66b241eb90b724ea339a6e7c142a3d792ad1ef0156a6fdd7cae9a54150c2719b6973c07d7bfc2d538995217e8f5e077c3f11357faf9572b0f102004814d5a4e6cc97b887592c7a713923e9762a21b22483e4203fb017ddc9818757cd8d87e40d3d008ef8ad3e04f65592fefad6acf5b3ba46ac3ab8f9797296a36dba9284a95afe88d8d98b307d2d0eb0632f49c4a6c42b8ce0428f8c8949455c39eec9d2861b97d0ab9c53db4ba4ee40b0c1dd7a65bc4e73163e03dbadb6b21128ef0ee562307ae68fe83c78a4ccf01b0d31070afd563b0a0b6ba48743ed31d0a171ac9054adaec51e16692a835b5f93374392a068d13a0c74042ee1c87610fb07f6f59745691ff692567f1c43cb636867a9d95ddff42c98a152b51cd464e9a5aab3605d70bcd0ffe53594ae28d12ab40bd2937cacbc22f70ffbf7474139a017be4761e4b7a4bb2262c4c3517
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(166379);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/18");

  script_cve_id("CVE-2022-22248");
  script_xref(name:"JSA", value:"JSA69905");
  script_xref(name:"IAVA", value:"2022-A-0421-S");

  script_name(english:"Juniper Junos OS Arbitrary Command Execution (JSA69905)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by an arbitrary command execution vulnerability as
referenced in the JSA69905 advisory. An Incorrect Permission Assignment vulnerability in shell processing of Juniper
Networks Junos OS Evolved allows a low-privileged local user to modify the contents of a configuration file which could
cause another user to execute arbitrary commands within the context of the follow-on user's session. If the follow-on
user is a high-privileged administrator, the attacker could leverage this vulnerability to take complete control of the
target system.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://supportportal.juniper.net/s/article/Overview-of-the-Juniper-Networks-SIRT-Quarterly-Security-Bulletin-Publication-Process
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?99086ea4");
  # https://supportportal.juniper.net/s/article/In-which-releases-are-vulnerabilities-fixed
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b616ed59");
  # https://supportportal.juniper.net/s/article/Common-Vulnerability-Scoring-System-CVSS-and-Juniper-s-Security-Advisories
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0d4fd08b");
  # https://supportportal.juniper.net/s/article/2022-10-Security-Bulletin-Junos-OS-Evolved-Incorrect-file-permissions-can-allow-low-privileged-user-to-cause-another-user-to-execute-arbitrary-commands-CVE-2022-22248
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8b2b5d3d");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA69905");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22248");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/21");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include('junos.inc');
include('junos_kb_cmd_func.inc');

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'20.4-EVO', 'fixed_ver':'20.4R3-S1-EVO'},
  {'min_ver':'21.1-EVO', 'fixed_ver':'21.2R3-EVO'},
  {'min_ver':'21.3-EVO', 'fixed_ver':'21.3R2-EVO'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);