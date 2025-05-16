#TRUSTED 053ee03412633a4083277cb2ea93ad1925e618f8ebd8d8192682ea534d353cb4562f70f2999e52c2a54f0af5acb296c0a8808d2a3ce2e6fb4ea1ec56ce271f8888577e2de336e4e9d7c750bb0569c4e647614ba1d7f89dda155276a809b6efa918d6325beade3325c4ff9218f5c5550ac08f8f3da33fe6831ff26080d41ed36b472c81bd76b60042689fac8272e572e103eba9e55fb9533328e8c91406a6af12bcacffe136f807c6dc1d5fded0a0055390742e6cfd1d3c5b93d1aca6e6d7dace9114369fe055cde6464212968c66b52c8a59d043876b9201a34ec2f817a44516235f71fdc660f37bbfb026a3a1c8f1cf546bb02031e691843c1dc9f5e84dc07591df4f8982544319b6d0fd52f686eccbd0df11aeb36defd4a78097c22ca9e039826053af9e478a9cc9b55bf543c67b9f4f02fdb8d8f7155947a75716442995f06ddcbbde709e92915bd4d64fc4ab6735b99cdcee45c86bf2c4345e4db2244637847c62339fb20aad1bc44d56cc4356d3ce84702ebaf48e321899b86f5790a81db28cdfe973bb658151c4ee69a5b475325246f25c3247af2c760fe787d675d4682d9e667a0ecee179b30686be8361b02148e9a01370dda37fa1b2326c569fdee05d95b743e0e33eef2825e5c340c4b1a8041c1de97d6aa008c111bc584104bc20d333493d5794e70406faa5845afed7781027261973e96b6aec4acebb0ef6f76e
#TRUST-RSA-SHA256 414cc1a6182c91ea8d2ad0fc87f2ede67b13ad061e0a91ab575a2d267234af1ad297526f0cd332b2d2c384f620139f81b6f70910bc8b97e04a4d0b05c4743fdfb2d834f71de0ba63cd43c16da50b7582cfd1c818e3e70fae4d4e0a26561897585fec01d5034dd495d08d795d78fb2a681dd73808e556e23716a6a739e1911e7e2171421a0106269aa3f854cc835fcd69896628915e627c475e4cc8596588cb86bba9b222af8f31dcc4f09d26bcc38186c270d764061a1f48dd6d5baefb32f01aed841d08f1050da71a809e8da0bd1a5a506c01a567766911e54d03e6860c81b4f4f23b7fed2eeb004ac0d192dc3c094ddee89c29debbf701c1020f13ad6e4459162c1f7801698b97e7e8e6053d5cfe49bc2496afb47c68f225242443ad1874a48db8c2529508be5796b17309923a89b045444d90ff2bfecdf5a8e20796272992f48c48aeb03d9fa7876b772ed91e6f0351757bec18da2c9c8abca788397543d5712416c135af71305e1775b3694531e911c3c40455bea9f0dcab21f8b31a67dc20332f89f6f4dbd1ac6816a7d5591d186ab7a6b96f498a0d0bef9f95db366ab096a6fcc46024efcc16db323a987c6ee1ed541685d2ab1bde237d416e6ae193d93565256e00887b10d3df827c51a4e1c7933ebd3be69b76741e0161c0be92f76373253a2a97e223d01b5c8be5c01f7a943e3f6e891676feb63bcab8f044a3a68d
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(137183);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2020-3224");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq32584");
  script_xref(name:"CISCO-SA", value:"cisco-sa-webui-cmdinj-zM283Zdw");
  script_xref(name:"IAVA", value:"2020-A-0239-S");

  script_name(english:"Cisco IOS XE Software Web UI Command Injection (cisco-sa-webui-cmdinj-zM283Zdw)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch (cisco-sa-webui-cmdinj-zM283Zdw)");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a Web UI 
Command Injection vulnerability. The vulnerability exists in the web-based user interface 
due to improper validation of specific HTTP requests. An authenticated, remote attacker can 
exploit this, to inject IOS commands to the affected device, and could alter the configuration 
of the device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-webui-cmdinj-zM283Zdw
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0aed7c77");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-73388");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq32584");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvq32584");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3224");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/05");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

get_kb_item_or_exit('Host/local_checks_enabled');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list=make_list(
  '16.12.1y',
  '16.11.1s',
  '16.11.1c',
  '16.11.1b',
  '16.11.1a',
  '16.11.1'
);

workarounds = make_list(CISCO_WORKAROUNDS['HTTP_Server_iosxe']);
workaround_params = {'no_active_sessions' : 1};

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvq32584'
);

cisco::check_and_report(
  product_info:product_info, 
  workarounds:workarounds, 
  workaround_params:workaround_params, 
  reporting:reporting, 
  vuln_versions:version_list
);
