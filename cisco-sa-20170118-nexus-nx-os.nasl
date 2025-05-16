#TRUSTED a56bff68a0051e16399eb1209f528e08b2f4d3f437ff8f6a8c8f9c6776810d6c4ac5dea0f380109148b9b56474de8f2b5bdc861242bad0b0318b8a81dea421e5429714d129984bd0540eb25de6829bbb235b0979cf9aeef4035437734e572b34c99f09ac58041143d68ddce61e595dffad3afcc02f96615979734a09ca25634fbb69b2c6c078dcbc7f0be7d201fa78b6d1456285648ccdeadc47bb097bdf53ab3c0166e6bc76eb4bf578ec62742abce420f030a0d08c07074b9b95f665a6ccf09629f1979b037214e3935874d944529a0a7713af32786f5a89063ddafa6ab026022ca64955287263e5970c74258040c87409d7738eec2cd667404be71990b27b05309e8e67c89ad8f67bb20065ae5055a53d44094b1ea578e2fc13a71abdf01faeb078393f7c1a91b4343ef5b493d8bc90c8cf90d9098565fe710f0c654ed1bf14cba5e390ee8077eb216384e64ed3bda9392248434fd845c92d1e1ca287052513418dae759ceb869aecf3d3fd0f4e59481b1a1e05b7f0076c1a4704c0ed576e05154d5dc29765091dc050f1b860c0b2ea932e7742bc51965ce9945ca1ce20d95b58a7cc1b6760405ce11c0d1fe3d8c61dce743c1a6e70b88d6d355cee17465d944ebf72610efdb04019c0cf9513b76b5639c96dd42aad1654e1c6dc96f233372442a516089b549a6675d6fa6a70e2418b63a6d014323f4167306d829fd04747
#TRUST-RSA-SHA256 953afcf5324a579658c1093b17f4a6c40590a2f88b447e39032510d6eb5b0097cb0a23846baa32a6f7bd505bfea3e744c0c9c1c23aeb89de1d0eb519fdab45f8d3d5cfac2bdda14b1cce3c8f0fcab8c53df485beafeb8ab24754c2b08ab423bd0ad6b57688c654f2df6dcbd9d84a3dd2b0e1e84703cacc5959c46522e6b2827ffe623a3f855127e01f74aef96a9719fae4e34636916d35b5879e95c1efa8a693fd07920d43e9c06046b0bfabb6c1fa7051758b86db12d7b76c22940ffdedc52a3a25348fe4f8bca63f0ea9d19a341907f9a5e568ba9b5d8356e9fd4351904b8ab7333126998c692cd269294787302dfb15fbba47613de6bce5226be7ecc458e6255d529ab2d13a76d7590571c451f397ae81350d99d46465043647899fb79c41027b00e79bc6a961393450f8b9c90beb1975dc649d5ec4bd862d89db0edce87b03d0da6b13aab5d3e6b045a5d77e7e3ed2debff2b671e54615f7e69231643db338f951236b19ac2519d231fae669b0b43dbaed4a7db8b7544b145db9464450c6b8ee6e0cbc46d0957df71f19689dfb9586161b4e4408ca2ac6f5d36db4f2254fbad1860fd73625086b36ea9c6bc0f92d8599ba6c45ec479eacf580f8f9d51754ed7cae4ff5499de36584593c82384d623ecf7b7d5701f6ab5783dcba94af952df39fa837b241eee7334d256870cf9a225e75422644965995b2ba0e2e5a1a07d0
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(102995);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/18");

  script_cve_id("CVE-2017-3804");
  script_bugtraq_id(95638);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvc45002");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170118-nexus");

  script_name(english:"Cisco NX-OS IS-IS Packet Processing Denial of Service Vulnerability");
  script_summary(english:"Checks the Cisco NX-OS Software version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco NX-OS Software is affected
by one or more vulnerabilities. Please see the included Cisco BIDs
and the Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170118-nexus
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?63c3627f");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvc45002");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s)
CSCvc45002.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-3804");
  script_set_attribute(attribute: "cvss3_score_source", value: "manual");
  script_set_attribute(attribute:"cvss3_score_rationale", value:"Scoring adjustsed to align with CVSS 3.1 attack complexity guidance.");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/01/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/07");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:nexus_1000v");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Device", "Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Model");

  exit(0);
}

include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");

device = get_kb_item_or_exit("Host/Cisco/NX-OS/Device");
model = get_kb_item_or_exit("Host/Cisco/NX-OS/Model");
version = get_kb_item_or_exit("Host/Cisco/NX-OS/Version");

# Only models 5000, 6000, and 7000 are affected as well as specific MDS models
if (
  ('Nexus' >< device && model !~ "^[567][0-9][0-9][0-9]([^0-9]|$)$") ||
  (('MDS' >< device) && (model != "9710" &&
  model != "9124" &&
  model != "9148S" &&
  model != "9250i" &&
  model != "9222i" &&
  model != "9509" &&
  model != "9134" &&
  model != "9506" &&
  model != "9396S" &&
  model != "9148" &&
  model != "9513" &&
  model != "9706" &&
  model != "9718"))
  )audit(AUDIT_HOST_NOT, "an affected device and/or model");

product_info = cisco::get_product_info(name:"Cisco NX-OS Software");

version_list = make_list(
  "6.2(10)",
  "7.1(3)N1(2.1)",
  "7.1(3)N1(3.12)",
  "7.1(4)N1(0.1)",
  "7.2(0)D1(1)",
  "7.3(0)D1(1)",
  "7.3(0)N1(0)",
  "7.3(1)D1(1)",
  "7.3(1)N1(1)",
  "7.3(2)N1(0.296)",
  "8.0(1)S2"
);

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();


reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , "CSCvc45002",
  'fix'      , "See advisory"
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
