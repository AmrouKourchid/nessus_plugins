#TRUSTED 4628f9f4a66a3fa042c5c935394a4eead37d7d3f59ef305d288376835c8d1843ecc33789920ebfabb091e7be5bee46ec7c0568c932e4a950eae9f2f885f87c140d9e5fdaeaf57dc3bd0367cd24dbfba3fc7ab9946c54d637a0d287b6713d0ad8fffb0b47258b83a5173da3f73bf8b4ffc28f9da584e474afb780119ed4bde3102fc5cb1a28b6b5543e88c30fbada1a5543e030efeefd9005cf75988237721a4895225998695f678afbf063ac8c17854b2b942cf51f82a0d430c7746905891fb2d9030b01e625eccff915a2d75256743a135ea87ed2e31ce2be6470a4bcfccfdc8e3619b1543a9b5941f990d0400214027834c9e4996ad15946a09c6cbe225d29b46fce4bac771fcf767680b2f949b4a9ee63ce7ef0cbae69f9539f0d07450f44d84ce3682716a1864b9bc756aafd4ec324a70798eedcd9283be83caf8737119de76e5065f0974f48a6dee592c78bd2312402f98e707fb831c55d94385813544ad25a391c4f14065029bcca0cf5f1d16ad48939944551faa5bd3e5a8f62d2c9de6693bd354a6181e5771f24ee51abfe1e04dc7b3041990e83c68d4551b9aa3c31cfe7114681e5cfe6333071ef3f242e7c8ae32d3efb813b0ceffeda92fbe6f0b6474720f2ebb1497bcb06b47295718ea1e429ac31340309cebf840898a1491672c58d1e1d0cb18c402826cb1935be2cc263ea3068a840ec241bb20f00ec86023e
#TRUST-RSA-SHA256 a97bd63167729fc6cdfe050c3ad9b32df653a3539de91ff78aa8e53aee4a43026c25fa185208ce7363d2fa7621568ed1635aba011cd802edb9ab496895cf62147e66298f5739ddd083f79e6881c30f8dcfa3d8eee373545c8522a6405af4a6726e6ea3301c22ac641bc0f917c6b72e45239d592548ab5fe09352e92264f4b9c71f337aa9b0da488e9b7010332d9979435487e0061d43205577b49b710c86ca102bc2e61b34aeebc7ddce3d29ea6c2080c10fe1695912fb78bb21ac6e6a86f3c77093f26094beeff492f3798d30427386e4e3c38c2f2a3b662ffecd4d36fcc522de48fc0491855d0e976e1121c58d4625a6da7b9996fc8f30893b8d6811d1572cbe06edb2710bf75e3bfa96cd53c36e5b8fe43cb798d60717b1586409e927c1412854e52ca38fb90a8a889ea244be03d8132e85193cbebed15feed85a8033ee6536d79834aa19998d136f522a5c4bf9858951000a7d2fa8f602426ed878e583eb1c94e8428f54de6cab940644b2ac484e878e6f636e56397e90b2ecce5020a6016133bbde7062d03ee687b61f6796119d6b81df19ac9e453d3202089882952dc7d75af0fe7b7c14e22ddc2c7115a52440a4bc8efcb90f1d5dab787abf1424744da970f6e51c1cbb70e99d51d0a10166f8ea6513ce578b8aafb8a3969e3bbe288a1b63ff40b28c3aaad9e9268bd08d47bb2ab4571ea1e04ae75001b13df75208a0
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(183035);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/10/16");

  script_cve_id("CVE-2023-20202");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwd91107");
  script_xref(name:"CISCO-SA", value:"cisco-sa-wlc-wncd-HFGMsfSD");

  script_name(english:"Cisco IOS XE Software for Wireless LAN Controllers Wireless Network Control DoS (cisco-sa-wlc-wncd-HFGMsfSD)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS-XE Software is affected by a vulnerability.

  - A vulnerability in the Wireless Network Control daemon (wncd) of Cisco IOS XE Software for Wireless LAN
    Controllers could allow an unauthenticated, adjacent attacker to cause a denial of service (DoS)
    condition. This vulnerability is due to improper memory management. An attacker could exploit this
    vulnerability by sending a series of network requests to an affected device. A successful exploit could
    allow the attacker to cause the wncd process to consume available memory and eventually cause the device
    to reload, resulting in a DoS condition. (CVE-2023-20202)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-wlc-wncd-HFGMsfSD
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a67b5906");
  # https://sec.cloudapps.cisco.com/security/center/viewErp.x?alertId=ERP-74916
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f3520ae2");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwd91107");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwd91107");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20202");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/09/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/09/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/13");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/IOS-XE/Model");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

var model = toupper(product_info.model);

# Vulnerable model list
if ('CATALYST' >!< model || model !~ "9300|9400|9500|9800|9800-CL")
    audit(AUDIT_HOST_NOT, 'affected');

var version_list=make_list(
  '17.9.1',
  '17.9.1a',
  '17.9.1w',
  '17.9.1x',
  '17.9.1x1',
  '17.9.1y',
  '17.9.2',
  '17.9.2a',
  '17.9.2b',
  '17.10.1',
  '17.10.1a',
  '17.10.1b'
);

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = WORKAROUND_CONFIG['mdns'];

var reporting = make_array(
  'port'    , product_info['port'],
  'severity', SECURITY_WARNING,
  'version' , product_info['version'],
  'bug_id'  , 'CSCwd91107',
  'cmds'     , ['show mdns summary']
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
