#TRUSTED 490a2be6caa4cfbeec8835c57acfa1bfa62ea6887f9cd62572e8bab143b58238b0eb12a20099c854c29b8e3246863a336acd647989f7e57873eff7b86c9ac18a5b4d940a0f46c0a02d6950392a12aebd7af72e5e36ccb2ab2f48330df6dee7a560790f2dd01666215bd8ba55a5efa9d47f3459a29df4188c3582e2f23a427de826e46fdeb164765a4a755d589cb01da232c64a12832cbd1f0ea62d5056283f14f840b67d8dbb220871e58225e7fe0ae1d8d73cfafe34ce84d9d94819463ab1b960036237f2c57f1fbf86997f6f04c7cb9bef5587dd7c181fcf4f4a339ac495d92e0499f8cb058d6e7e460adbe03534b88cda8151505154a257ad2df42f0187ea6fb9297035199be9bb3b265556ab6c22c3a6bf1709e35feb297228406919e7d5502ab9f1cc7a6040d31a9f1ee60a04cca78dd77ccef0ff0145aff4c4584744f29729bea0444f527f1ad4bfee1d415f2aa3e260230d3124039664eab895ace58bcbbabb563b11fb042c0f97cd2729d4cb8e77773582409de2576b6e4e5c7f76efc381cf699f6daf44fceebe938a4bae2435cae5d7899ec1dbda08c1cf60154f3bccbf8820826f2b92ec284f0a00ac9dfa27a659585d2f02fd19d1490a2c07d4bc2bdc9992267c4dc8ace9fc1c4b727df0b2e510fa3f7499e95fc98ee29112fb7f48f4f467afe259a374863e951b6907521a444e03ca2b1e9822d568323d2c8bfa
#TRUST-RSA-SHA256 4556ec69314286af7e2979410db18de9b663d891c53636281d38a286b405c18347daac34fbd6995e9860bb7de009e91224dad0cf4339e8fc4cd8c1e85f955229c8bb15959825aecf11053dddc9ab3f6dc909232c106e3b38ade986093b3d18318f9068e528855069c7e7ea27a6697fbaf550c7d5d4cac0aba9658d925a5bf227b36de488b8fdbf0644b9e662c590467f74fd6bb1acacf26cfb1d5af1ce0fb1ebb1127a95b32e401494ec78bbc7d9e1a3e1dd8b29670f9f32bab0b6299eaca2aac801bff8b86439368fa12d025fe72a5e39c65d650a526f09ba9586e7bc41b11b7433d48ded110edd430c5d66b7e690a9e823d44fe19b7981c38d04a812f6d7a45f79b16270ea2f5b8dc29f0f05c367db9a0335cc9ad21bb41b37c706a628bdf97e8dcb79aef1502053e902ccf213fbc6cc39c9b77f04fd12878f1e021c6165e5a725deb370a6753392022cc2282e0c63364b0057ac189ea94d20ccd74b8e296c0c128f40cdb1af7b6e0f5790e555e96a6bae9f9daca9e08306d13348387ccb29cc4838a61c2dfddbcd65b36560dab41b9513621e4b8549880433c64a053c0d154ab6a39ea6093d70dc9ec9f9b2fcb1fbf543e37713fc03f011fd3bfe831108e9b01ab9308d1443e1d38fe60b2f23749994a22b6b95e2a4f9ded692af2d613848a6ad945aae3d6cb2783f17da6f4da208e3f4da1e2910875c74386e441201b06d
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(211998);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/02");

  script_cve_id("CVE-2024-47507");
  script_xref(name:"JSA", value:"JSA88138");
  script_xref(name:"IAVA", value:"2024-A-0650");

  script_name(english:"Juniper Junos OS Vulnerability (JSA88138)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA88138
advisory.

  - An Improper Check for Unusual or Exceptional Conditions vulnerability in the routing protocol daemon (rpd)
    of Juniper Networks Junos OS and Junos OS Evolved allows an unauthenticated, network-based attacker to
    cause an integrity impact to the downstream devices. (CVE-2024-47507)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA88138");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA88138");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-47507");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/02");

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
  {'min_ver':'0.0', 'fixed_ver':'21.4R3-S6'},
  {'min_ver':'0.0-EVO', 'fixed_ver':'21.4R3-S7-EVO'},
  {'min_ver':'22.2', 'fixed_ver':'22.2R3-S3'},
  {'min_ver':'22.2-EVO', 'fixed_ver':'22.2R3-S4-EVO'},
  {'min_ver':'22.4', 'fixed_ver':'22.4R3'},
  {'min_ver':'22.4-EVO', 'fixed_ver':'22.4R3-EVO'}
];

var override = TRUE;
var buf = junos_command_kb_item(cmd:'show configuration | display set');
if (buf)
{
  override = FALSE;
  if (!preg(string:buf, pattern:"^set protocols bgp group.*neighbor", multiline:TRUE))
    audit(AUDIT_HOST_NOT, 'using a vulnerable configuration');
}

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);
