#TRUSTED 900bd9d6c138b2c3322d70134acb44a7053ea0c65fc3d35583312edc545b832b2977f0da47d9d02cb8b23b5d942166650056e8036800ea3a9c55e41576759e273e67f85ab400a154bfebdad009337353f2d99414eb5e2b4566afac47c3694135e769c08ea33c74f9f68098e6b245b3ee5514ee9ada5243d2af3da7885883d03d51dba780a85f013c17faf2064eb054633ddf94d239e8eb2eed3b8fb899841d926d7838509d521ea3c119fda5d6f05f9233f5b266d79e2516a5341a7a603abb445654bfffef08e5ef613da8fcd22c79b8c9f3ab4ba92c802f9c823300f5724d02455986976cb9a0fc6bbbb626626fbdd664213f576d48520abdf49735eec43430c3253bcdd05aca07e49670ae560534cfd95ba452327ba2e7d6de843197a7b53b8fea0e1d1cb403fa39072c0d1fe9fa88a1a7216b1eaaf325116c68acb55861c5095e8fccf59bf455c322408deb521873700059d10175056359bcadf247b8839d8d0b7989f3d953476a604f890d0446e0c014396311e2371665227071771778154ec7a2eb9490c5eb627763e4f4d0a1fffa52e44ec7531434d1baf6b3be1301b7f8cd218e573e7a75dd987164f2fe1a6e374f8ef98b882fa6552e79ca8b6ac92612490ed3ed740cd14f01d3801dff4efa9d9754a76380822c7fe01e2acd67fc59ebe1944428a9b0774b2b482dd90840b95a1b5b25d933fd8248c1412873023954
#TRUST-RSA-SHA256 3137b1c1d56f6132c0ee23f4f0078f146d6af2be8433a617f95fefc24f91c4f836fd3987efe4f820ed64d295fe2edec8c6291075c121b360db4e635bdca35cab1e8c8d05a3a63088a4705e3f3ef22cd8a3142e8268333e3a07b0e916e9d85d561ebfe65b4671aee547dfec7178ced22c7b94ff50575eec3379c089d033a49273adef6e981b79ea45f72b3837832cdaad4a66b58e3930ca146339dac545f890d154c9fa760017423bffbca0bfa30dece72990ae1b0d56a005e1b8c01d2116f3b5e9f78ce14b960d1d61e4158f2c1b075fea31f4c7e08f753f078dd115253d2142d15e3bda6184925f8f804dbd3b6ef84ee0b438f071b909bdd9562d9f588fa17ec74d132e4d906e5988e701ba812fa2184b945e1e291ec94b2f888b2ceefe96738fcbee8ee1fb4f55a797f7aa80b7f27035c6a33a57efc5ade3538f5dfe1e773dde1c6dd6fd368f31cbcde29f0ee920b0aa0de87012a96871115193aaae07345d9318ea9212aba3694cb3aa1c77f387718c67507c60623472d51bf160001193252f9a70fe4fc8537988ace885a16461b371f4840984e950e7e2e0da6b8cef553a3838c0e65f2acb4bc4357e6c767e39494e1b01b3b56b4e70b71cc434fc281322a35ff9b43d20bf4a5fe94a05d0bb2e00f723b72a4c29d34fb95c706621d465dac0fcd8b4cb7d0de125b85f928a4f20199f5e05977d9edbfaad950a3505d51d9d
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(133723);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/18");

  script_xref(name:"IAVT", value:"0001-T-0559");

  script_name(english:"Cisco Software Maintenance Update Enumeration");

  script_set_attribute(attribute:"synopsis", value:
"Nessus was able to enumerate installed Cisco Software Maintenance Updates on the remote host.");
  script_set_attribute(attribute:"description", value:
"It is possible to enumerate the installed Cisco Software Maintenance Updates on the remote Cisco device using the
'show install active' or 'show version' command.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/14");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl", "cisco_nxos_version.nasl", "cisco_ios_xe_version.nasl");
  script_require_ports("Host/Cisco/IOS-XR/Version", "Host/Cisco/NX-OS/Version", "Host/Cisco/IOS-XE/Version");

 exit(0);
}

include('cisco_kb_cmd_func.inc');

var buf, pat;
var ios_xe = get_kb_item("Host/Cisco/IOS-XE");
var nx_os  = get_kb_item("Host/Cisco/NX-OS");

#############  SMU format differs by IOS type  #############
#------------------------  IOS-XE  ------------------------#
#       C9800-universalk9_wlc.17.09.04.CSCwh87343.SPA      #
#     isr4300-universalk9.16.06.01.CSCwf49531.SPA.smu.bin  #
#--------------------- IOS-XR / NX-OS ---------------------#
#             disk0:hfr-px-4.3.2.CSCun00853-1.0.0          #
#   nxos.CSCvr09175-n9k_ALL-1.0.0-<NX-OS_rel>.lib32_n9000  #
############################################################

# Lets get the SMU list first
if (ios_xe)
{
  buf = get_kb_item("Host/Cisco/show_version");
  pat = "[SMU|APSP]\s+(CSC[A-z0-9]+)\s+[0-9A-z\.]+\s+[C|U]\s+[A-z0-9.\-_]+\.(CSC[A-z0-9]+)";  
}
else
{
  buf = cisco_command_kb_item("Host/Cisco/Config/show_install_active", "show install active");
  pat = "\s*(disk[0-9]+:|flash:|nxos\.)([A-z0-9.\-_]+)";
}

# If 'show install active' fails to return for NX-OS we may be able to pull SMUs from 'show version'
if (nx_os && (!get_kb_item("Host/Cisco/Config/show_install_active") || empty_or_null(buf)))
{
  buf = get_kb_item("Host/Cisco/show_ver");
  pat = "([A-z0-9.\-_]+(CSC[A-z0-9]+))";
}

# Now check if we failed to get the patches
if (!check_cisco_result(buf)) exit(0, "Unable to retrieve patch information.");

var split = split(buf, keep:true);

var patches = '';
var report = '';
var line, match;

foreach line (split)
{
  match = pregmatch(pattern:pat, string:line);

  if(isnull(match)) continue;

  if(match[2] >< patches) continue;

  report += '  - ' + match[2] + '\n';
  patches += match[2] + ',';
}

if (empty_or_null(patches))
  exit(0, "Unable to retrieve patch information.");
else
  set_kb_item(name:'Host/Cisco/SMU', value:patches);

security_report_v4(port:0, severity:SECURITY_NOTE, extra:report);
