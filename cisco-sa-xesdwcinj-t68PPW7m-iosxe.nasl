#TRUSTED 02f341ad4996b53f9cadcbacefc7f0abdadad0c2007fd8c1aa4a85f71837e5ee00ed9996a4a295ddae6a7dfe082d63f2449c3a2d1279a0f7dba34e40cb2e647a9dbae8889f9700a1ef2aa0288a825f9fb4d25e5e142a41d8a9023869699b0b151bdd6d4331877784faf5b3976abe36a42bde01449a6233e02756d18b2521f5e5a4855fb3952659046139cb423f14f26ada8539c78b9754f562255972d460194aa2aa75ef3a7be1b7017cb923297e4e2c2adf03fd96f90c391d1e87bebcdc69e8f3d759bccb412ce1308b7e01a8c7c14f947d3c2193757e9601db47270dabfd922de0da442d4c7e06528b746b067b2e369782b9a0bd1618c0bc9c1ab0f65604e8e6229581e1aa0f6c37e77024770fcae9e6a90a3875b23da861f38cc41cf443f37ae5858c6b561f394f0f13d99557a95a2e64a86255d9855ceba3c922a7fdfeb734cc33d1b53cdbdb5db7a49c68a96abf33293eb278f9e80a4859b6c3726da6d6c087a1228369c20523c57c9653c0bf5cdce4c96183d179a0368bee1b4147dc7e406afb883a85d765d5874fe97646d75219c02d83ffa61a0031d1dfc91803e7906a0f2a07d7bfe4b1a49a0d0f7fa33fda9830ed9c48040e05f68ec9058afbfa6f7d9a27cfd8866ce9d04766ec3c6c66dde37dc7966c16eb362b702df7b7a325bc184b21a477a6bcdbd27457c4c40cf22783c0c9efbcb26bcb64eb0227828be6a8
#TRUST-RSA-SHA256 426865769c0af857600f2aeba0806b0b41aa5f88e06b4f62aa33f2649038eaf912aa93b757f7ad6c7a6a1346e6d49b1ff4ea1bb3d47c63db4d09e43a952ce947c058fe9f9aa16574c67fb6436147681f3b5e3391fb6d382e37796f2eec5a704bc3ac7ac257b1687e36af776ba7b7282e2f067812a8d4e18051941260822b4e13a5116c6ee75e9143ae2bbfb532832f1275d6236e57016df2aec9c683afe7211e744fab5eb3c0808c2b9b7774b17ad640a05ab6472b071495f229ec223ffa041e1b34d903242286adc2167572721031372acd8e29bd5f982c3ffb790e26892a4b9b9a2bf8e4f4870bc7cb74007fd2ce20d01ad0ff5f504bb0c7446c860455c699c72af17cd2e0cc44121f9f3b4a35c0ff38a900496a3f52a013ea2a0f4b039b9e17eb02a31e4b908f5d172d6d992a1d006c6e4a0c6a0b94b04b9e201ae91371238624f219226e41d8723a8c8974bc86d994cecc6d93fc36d092ec71e5a263495cdbe4d4b0bdfc2f2b8f7879b7c9eacb69899f9c7a0ae917e94324d3a5ccfeabd16df2e39ca756404fb0390dfd44b2067815bfce50e91245877dd334b9976b9a1dc9b3725655c83911b5b825bddb943a8d1180edb684a3f9f99cbc4e5aeb6a628e61602449707e7c25309d6e8340db12078be8ad6a743cd71adbd3879b7697a3c87cee8f4078f458cb9fe587de45669540b8ca83faf005cf0524fdee35a229991a
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148090);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2021-1382");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw64828");
  script_xref(name:"CISCO-SA", value:"cisco-sa-xesdwcinj-t68PPW7m");
  script_xref(name:"IAVA", value:"2021-A-0141-S");

  script_name(english:"Cisco IOS XE Software SD WAN Command Injection (cisco-sa-xesdwcinj-t68PPW7m)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS-XE Software is affected by a vulnerability. Please see the included
Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-xesdwcinj-t68PPW7m
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3f7dd1e5");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw64828");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvw64828");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1382");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(77);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/24");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/SDWAN");

  exit(0);
}

include('ccf.inc');

get_kb_item_or_exit('Host/Cisco/SDWAN');
product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list=make_list(
  '17.3.1',
  '17.3.1a',
  '17.3.1w',
  '17.3.1x',
  '17.3.2',
  '17.3.2a',
  '17.4.1',
  '17.4.1a',
  '17.4.1b'
);

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'bug_id'   , 'CSCvw64828',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
