#TRUSTED 242521ff2b619c2ce0b86fc80922b765ff58a424627a8fceedc6f92c6603a25e7dc5491e40b49003600ecc1b32150501812fb27883f051b812a7134c70c8349938d64b59d87720e286e9a683bb20db40fdae03b5ab91c3a552fb3215acac46f6fc5afb4550ae7f9cfda44b1f592edc2fa2e787a3772954a0031562f54e6700bf544e8e22d9be7e311bb4302bc950f4bd7685ba0d2f1ff8456ff8dd3e74a7220c0bb33820c6590f5b0cd4e293c4bc7ceaf54cf7ef63ac09d7ec16d64a899841f81115605d540f15ef381935e77f01705b0a868421f94e9dc6c01360c3c237d4d7533efd0ff53356d4cfe2fcd7961e6a70f665730b87284dae227c93254ab659b78a8462f905568225c221f86500978bf763d0d1259e61d87809ef2a04e786d192dea87aa32079797d0e4c1ded9b061534771487052cebda7bf03cc4ac7dec04be91fc52e89ddf83218f4460d9cdba1c7488765144f8582341b8a01ab27420380d4c20f6cb686549ef3558d3a66958f6a55b4a16c7c86ea27abe4e9b9ac13d1d289817387a828047c5cba2d9d685a87f939b7b41ed0ddeaf5d202f16f7f506b20ae3a10f54e38fbafd23f5f5ba771f6bfbe7231756ee8d5ae4fbee4609b648ff2006b09ac730bbfd130ed9e02b842662d9c5da4be21ca4d42e495fe123dff05f63d421225b2df781d887aaf74aaa6b978c5e3322b758955a6cc47dcb282998e925
#TRUST-RSA-SHA256 40e61bfef80bdbe242283fa796dbb05deb394baebf82bcf84b49cecc43f767ea6669098d58e53d0885c0471d3e942b6bf9a7e8ec79c02da1ca9420d04d1b9425a571f088e0d3bf2ad6ab5bcc8bc325f116aaa3249619407b7febe6b2a64592b744b79d8328f390f5affb9f03b5175c6c7d41c02b0a2b77b8719d06349a725a717a9da7bdcc6ad1238713f6b0a87fe56d64ea2c4de3da47516c6c4606598995ffce17bf08f85901cdfe61f68ca22ad16a0d6437177bdfd3012282ab99453d5e8c215130ada4b2c22e3906095f07b918f15578ef67aedc9a9297c24d9f4fb5bdc395beb4a0bf9c8d598e2026b45d35c0443860c3542b7fed6777348635558190b11b298fdeeeab0a0b8d3d159a6d9d345bbb046cc8c138b1c7e8abd5a14f2b2cb543408289cb679c95e70743588f7080402a57c92ed5498b0f47fa5102f81489a528613f51c46f0b8649834e44c157efe8778e77a8275b9bc5ed9afa3de852a87f4ae1a95fcbad1e2a3bc932dbbc7ec7211a646ca1e8e16c64e4bbc40a0cf4ba63b5d928debcb501e814fd6def5f76a2cf06ac90dd4a2b31e1564c4879d786eac18e05a246468ee6caecc129e113ea630feab2b4de878c4124b9f5ac4e466a6d6fde9b90fe1720f91292f5589ac2903be81730e69ea2de2508aaef7d7e4be8ccf14ca9987bb7c295046e8e2045802da96ebb7a635c809ba34145d5e023867fa0ae
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83733);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2015-0710");
  script_bugtraq_id(74386);
  script_xref(name:"CISCO-BUG-ID", value:"CSCup37676");
  script_xref(name:"CISCO-BUG-ID", value:"CSCup30335");

  script_name(english:"Cisco IOS XE Software Overlay Transport Virtualization (OTV) DoS");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Cisco device is affected by a denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco device is affected by a denial of service
vulnerability due to improper processing of oversized Overlay
Transport Virtualization (OTV) frames. An unauthenticated, adjacent
attacker can exploit this, by sending a large number of oversized OTV
frames requiring fragmentation and reassembly, to cause the device to
reload, resulting in a denial of service condition.");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=38549");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs
CSCup30335 and CSCup37676.

As a workaround, limit oversize packets across OTV topology.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/20");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2015-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;

version = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

# Check model
model = get_kb_item("Host/Cisco/IOS-XE/Model");
if (('ASR1k' >< model || model =~ '^ASR 10[0-9][0-9]($|[^0-9])'))
  audit();

# 15.3(3)S1 maps to 3.10.0 / 3.10.1S
if (
  version == "3.10.0" ||
  version == "3.10.1S"
) flag++;

if (get_kb_item("Host/local_checks_enabled") && flag > 0)
{
  flag = 0;
  buf = cisco_command_kb_item("Host/Cisco/Config/show_otv", "show otv");
  if (check_cisco_result(buf))
  {
    if (preg(multiline:TRUE, pattern:"^Overlay Interface Overlay", string:buf)) flag = 1;
  }
  else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
}

if (flag > 0)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Cisco bug ID      : CSCup37676 / CSCup30335' +
      '\n  Installed release : ' + version +
      '\n  Fixed release     : See solution.' +
      '\n';
    security_warning(port:0, extra:report + cisco_caveat(override));
  }
  else security_warning(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
