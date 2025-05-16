#TRUSTED 7a97bae08a2cf6a93bf141000253ee0a72cfed82f7d5cc5f5220953f175b6a3f59780a0ce38edd758e9df2eab6c967520d583b3a7c8d89c0c7a4764121847faf4a941514786870217910d3edc133b90acfd08a9158465aaa4e34829116c6563698c938360a8eda0f65dde1416f84c18e60f46fb0a9848d250768b58b3f4bc32b031e7d3c2ec2ab3c40553f92e14a9b9e9f0cdf76e2f3545e549aad59483e098961e36436d1825e10d040948cd3c23b2969d4b97e9f64f296e892959653dce28883f5bad29b97b03afdb298fdb2b8d987fe3287ff2d6f7e7543191d4e39cde027aba66310898d5c72de864630d3dd1020cbf8b2d5b2a410cfb007398013b2c319c03d24089e535d29b62369cbc49fef81f7a68c48b607d71a8732ec6019fc2e6c4bf04b64e75a432f52fad50a393e8a96a0fc1efd029d29ee8050f3b1abeff04094060bc9f5fa699a4cae595dcd7df3725f9e359ebfe9c04b1879a8543c4c2eb900f2bd247c174437f62bc0ccc16ae6163d4e0c1f9a72265b712c2b51bde89e51c87da6967319159a092b07709a47c8af5bc6c1083632383dea4896bbe17d660dd8ae1667229350cfe622085497b1bd67c38a5063565466abda45a499ab2e5a7f1f914a459199098ffaae792b3ac669dfcaf238a1b134b985cb880413be0a194f5338cbe81e0c8f4b45e6792314cabfeb0f29581f75eee41110d861e42dbe3d13
#TRUST-RSA-SHA256 9bc8b44de7e1a18562585d170098aa1fa4e572455ee56fefc2cad33f5b5e0e0f292315fa26355da0484f1e6266d3934d62aea8c95ec1c5e9dee00e60156844c8c864b1a00556ae2aa6ad51ba793bb388592fbc84342721839abcb305cb08f2116c2348ccab2176091e933900c03e44f767e8589407500373f622f5679d50611c04474872b4a24883a8ec0a700f5f4b7ca8ff8da45fd6ba9cc79e516842fa4e90a71696effb403f61cf56f4ca47b54ebd1e47e7ae0c443f6d120adfad3e662746fdf5d01abd26b86b317eccc97847dd38b6228505e3e38f2456a253730ecd65de090e260fccc11927b7a82f135fd1b7c467c7aa30c235815ad2d9ec973c232f10b1aa0e4cd5ed3dc09b508b37afc4fc44cc98573fda05649ec321734d2b729e61f1d9e063a78d8258aa826dc6a2310d8dc573fcd43b509c5890936b5018e1040670244fbf5b7dda45d24ada40c7c4f4d397119324343bca0fc920c0180dd1c7b6bfb82509bbcada6b0297fb5fb4b52d79cc28029c37f2d2a5c1a80d0ec993d2cd8db854c5474d80b41dd84ab33c40f2089c9f5d3512df4519f7e5089e817b22ea7aa3d963bbbf268047c820f8bee0fee6295092a4d8fdb5405aa414f80b4553a2aadaae0c7d80006a2ea394c1fc552c4a8c3a5d85a329091028bf5fd59779dc0bac725f9bdf9be35c9c9503b39c0e7a56533818e6bad8c91aff84e686a0076c83
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(166459);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/18");

  script_cve_id("CVE-2022-22211");
  script_xref(name:"JSA", value:"JSA69916");
  script_xref(name:"IAVA", value:"2022-A-0421-S");

  script_name(english:"Juniper Junos OS DoS (JSA69916)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a DoS vulnerability as referenced in the JSA69916
advisory. A limitless resource allocation vulnerability in FPC resources of Juniper Networks Junos OS Evolved on PTX
Series allows an unprivileged attacker to cause a Denial of Service (DoS). 

Workarounds are available as referenced in the JSA69916 advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://juniper.lightning.force.com/articles/Knowledge/Overview-of-the-Juniper-Networks-SIRT-Quarterly-Security-Bulletin-Publication-Process
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?00a9cacd");
  # https://juniper.lightning.force.com/articles/Knowledge/In-which-releases-are-vulnerabilities-fixed
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?812ee185");
  # https://juniper.lightning.force.com/articles/Knowledge/Common-Vulnerability-Scoring-System-CVSS-and-Juniper-s-Security-Advisories
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d0ab70e2");
  # https://supportportal.juniper.net/s/article/2022-10-Security-Bulletin-Junos-OS-Evolved-PTX-Series-Multiple-FPCs-become-unreachable-due-to-continuous-polling-of-specific-SNMP-OID-CVE-2022-22211
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cd773fd4");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA69916");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22211");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/25");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/model", "Host/Juniper/JUNOS/Version");

  exit(0);
}

include('junos.inc');
include('junos_kb_cmd_func.inc');

var model = get_kb_item_or_exit('Host/Juniper/model');
if (model !~ '^PTX')
{
  audit(AUDIT_DEVICE_NOT_VULN, model);
}
var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

vuln_ranges = [
  {'min_ver':'0', 'fixed_ver':'20.4R3-S4-EVO'},
  {'min_ver':'21.1R1-EVO', 'fixed_ver':'21.3R3-EVO', 'fixed_display':'21.3R3-EVO, 21.4R2-EVO, 22.1R2-EVO'},
  {'min_ver':'21.2R1-EVO', 'fixed_ver':'21.3R3-EVO', 'fixed_display':'21.3R3-EVO, 21.4R2-EVO, 22.1R2-EVO'},
  {'min_ver':'21.3-EVO', 'fixed_ver':'21.3R3-EVO'},
  {'min_ver':'21.4-EVO', 'fixed_ver':'21.4R2-EVO'},
  {'min_ver':'22.1-EVO', 'fixed_ver':'22.1R2-EVO'},
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);

var override = TRUE;
var buf = junos_command_kb_item(cmd:'show configuration | display set');
if (buf)
{
  override = FALSE;
  if (!preg(string:buf, pattern:"^set event-options event-script file .* source .* refresh", multiline:TRUE) &&
      !preg(string:buf, pattern:"^set system scripts (commit|event|extension-service|op|snmp) file .* refresh-from", multiline:TRUE) &&
      !preg(string:buf, pattern:"snmp", multiline:TRUE))
    audit(AUDIT_HOST_NOT, 'using a vulnerable configuration');
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_HOLE);