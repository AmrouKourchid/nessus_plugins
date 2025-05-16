#TRUSTED 63b5719ffe90311cd3e9dfa240ff7377340055efe8f08dad24e2eb1bcffed0de7c8b1383577ebb10629dc0519bcd9620f494817ceaf71eef0c04f7d532312b80a71fa214c9b8ae91982bf490ba70cf06e9242b7a56a54eeb9a2ef7fb7d5db393bba86aa7939117dba1f2f283546668ff168da0448073462d1556d959b94cb3e8018edf764f5ef7e65e79999c57a78d38ef6d42a6c1e647b5eefa1bb0bedcf57f563aae3b66b048746a66d4f8834452ebb3e1d0763c74bb41544bd83a960672c6c6020c1b69dbd7f463950a0f197d88ec6b46dddee3bb6005e31ee9fb15695980c7e9ad2baefe8a69c358b1dead0cd1f53b07859d789df137d4efdadfce6df53bb441513de571396545f0e2b9eab741a67e4d4c17318ed81b1d300d1ed984ae4159379e95caf843dc3ea84000fa08d8784a92f97f728c666e91ab6165d9d77054f27bff2b8453dcb03661c9b99c880d5c34dd41dee70cafdc10f847aec4897696e0457d3a3078e7815624be6befa23300df2c105636053df98feee5415b9bcc128c23c69c3e05831e029feb6d7ae98bc5b56b60c211a0f570654252465cd97c1ea84e3f3329f851b838993ee1f7b229b4f0afde84f5f20bf1fdfcb4836bcb61201d66895434061beebd57d41ef21e47983422f9c695b52680dafbd7671de8a76d9b9d19512c4a27de8168c2a7c94a3b0a42b1dd423ce13a1899775e9c1a6039cf
#TRUST-RSA-SHA256 12c33934bb96ca54d4a9dbd5503daa9982029c395213b807dcbd10281f1984f54b7f121da222e1451c0c557298b1625adc3ebe42bd5c5f85d13e1fb0a85d8533bfb0b916d778a4cd1d7b518e75ccb6df7dd3a9783f9d659e4e8c1aea52926b4eda51f5610b7e7651da41772695ea659d8edec0a96c794f33a3d3df89d3888f651b69dd61e68d176b62cdc2514450c13c7dff3791e5ca78d9206c32cb711672770a94ac997e3697c54477b6430b7544d6f539fb8a8fc064ae13cb40106ffd6bb9b8911ec57d94545d0f8ef672d166a953e8499ae555c32cfad1b62e5a81d6705794434ee2b77d381cab3b1e3d1e707d21d0401153f0f5bae515fb3347a665f77f9e5c8024a9ef83fd7f92ccdd9c67aada8c2f9675b0d3fa011e7f5777dce99e80fc1a50c0172cb6c19b49799764a3664ed2b5d7a1d19adf0a68cd5d0e3835e715323a4361de283dbf4346e444fe4b7d1575981ca800aeb9037f3e7b2570fe23df4aa0fd4a41eda8553687a8f3f8e6b85d87a411d649c0e21cbeca72fab2be8b35bcce1abee86dbe8cd16b420b4948964fc5c326cb607187b0f5e1edfdb60a51e91fe3881e1f629fb17bad1c45257079e5c795dec55cacc312c31db46f591d3f35cd6062e10e8db92eeb5336b8de2774602904bbc78be7d03f708480651a55f8291c3541f3dcc3b5beae10195564753124e068fbabcee5afa8b3c6a4ec59f4bbaa
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(160089);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/14");

  script_cve_id("CVE-2022-20695");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwa43249");
  script_xref(name:"CISCO-SA", value:"cisco-sa-wlc-auth-bypass-JRNhV4fF");
  script_xref(name:"IAVA", value:"2022-A-0174-S");

  script_name(english:"Cisco Wireless LAN Controller Authentication Bypass (cisco-sa-wlc-auth-bypass-JRNhV4fF)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"An authentication bypass vulnerability exists in the authentication functionality of Cisco Wireless LAN Controller (WLC)
due to the improper implementation of the password validation algorithm. An unauthenticated, remote attacker can exploit
this by logging in to an affected device with crafted credentials, to bypass authentication and execute arbitrary actions
with administrator privileges.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-wlc-auth-bypass-JRNhV4fF
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5f3d9738");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwa43249");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwa43249");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20695");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(303);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/22");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:wireless_lan_controller_software");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:wireless_lan_controller");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_wlc_version.nasl");
  script_require_keys("Host/Cisco/WLC/Version", "Host/Cisco/WLC/Port", "Settings/ParanoidReport");

  exit(0);
}

include('ccf.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

var product_info = cisco::get_product_info(name:'Cisco Wireless LAN Controller (WLC)');

var vuln_ranges = [ { 'min_ver' : '8.10.151.0', 'fix_ver' : '8.10.171.0' } ];

var reporting = make_array(
'port'     , product_info['port'],
'severity' , SECURITY_HOLE,
'version'  , product_info['version'],
'bug_id'   , 'CSCwa43249',
'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);