#TRUSTED a2f8b30fda7737dfece706eee5a26bb7dfd14c29fff2a27d9acfe282f8fb71be6223808a6702e6f7f5ceaaa173df892e42198573c29c2ba35e384f6761deed240722180e301389c06a3efc2b4fbe3c2ab8e254360a60b4155eed468596091a7a235cd66773a5e3b8dce72dab0236ad1a2ba7be4f6d7e4bb6f7fac7219da2520610b8f15d09b222d4c0d0a1dbc29042a7c04f30f5629d02ed09513a0d0ad3ee2218bc961447434469bf441f7facbdd3e7b342017fdebf56a86db5b10e50016c917c21bd94c2cb453a1f5b2a851204ebc8c21ec3ed04ca0f2280512725c2a0d4867ab8118960777e3ca2412c4bcbcf82288bea8696d7088d9239042bee574c961213ba416b7d92cb151387034ea6bb983e734f7e90dac74fa8182c21f695761c0c6f4a7b73f41cd52d3f173e49982d2fe819b456abf69c368deb671b17d9635d9c31b7252ebecf0d6efe8308fceb7c08358f4a2a0d9458b8fdb74d7580292a6960d90b3bb5d4bb74d8d7fe66948b5c2e29635dc5a23a41b96ddcf878322fb01c71eb48aadb4a493a7a60b5b325365a259d223ead18f165289412fe21b89429c24b865d67855a4e44058790306a3292b90b293a2708c37f468b32b68cb95dfbef2b2cb7b1cfcafe36565c240a03c6ef179ae8d2f869db0c1b76416c6ec672deead67c891b49ee534e1e7acda3d928e4323a51ed0754e8fd507b9b0003b2e2100bcc
#TRUST-RSA-SHA256 3879ad0bec5f01725ea8bebfc956c53136480ac6fcc7e8cab45969f8636d9eb2544590d8163b5121e785fa29d3d032cdb6c80a6e04f2103cb54c894b617500f6cd3da1ed86ffcf723107e92cacdff714d1cae6abe8599e6eeba421cdefab86ae6ef49ffe01f1f6bb27cfcfe94cdc2e6ed3125fa4dfcda5d4990cf660824f0de7c00339d14a977305524e2d4c0c8a608776c2dc686cf28eba5f37926d4cc81eb4b26869d07ed8090ea43aefd148cf81e2a7dc73a1148bee4b88c00a25a599756f0827d124317f60fc7a2f5f0baa40f6bb1ef7eb7febf5268042fc9942db97250ee384c8fb0906065c8441912beed4817960f8ab236abd84cc9b696f87e5bd82e13420e67226db54a932b063647b8059aded3994b9b28945c67e3c63791044f8b4e129801981a552a552e6b3dda78dbdb7f137d091c89a4f3591d6b87625ecfa28255487818fc5d84b6d5216c7daeae7420e2baf00f28cc14f8cf470828394d86ef41259652250befc659ad6c689264e7ec95fdc24505ffaefa7b0aa782403a69196a2edc23fa229220f003aeb67d7cd8f330cbcc67d11986a8049872c4f7f3c87ee0beee7fe11692b43446ec669d92b5b6d34f5f5e5b90907b7a76c372fa63ffb420272e161f906b4b62885c770484432d1c8722f79d8a24c1b9d25d894ac37699305b55fca48914757d38c3530cf8914b70c98ba3e75b7ad511e512c3b75868f
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(179741);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/09/20");

  script_cve_id("CVE-2023-20121", "CVE-2023-20122");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwd07345");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwd07351");
  script_xref(name:"CISCO-SA", value:"cisco-sa-adeos-MLAyEcvk");
  script_xref(name:"IAVA", value:"2023-A-0065-S");

  script_name(english:"Cisco Identity Services Engine Command Injection Vulnerabilities (cisco-sa-adeos-MLAyEcvk)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Identity Services Engine is affected by multiple command injection
vulnerabilities:

  - A vulnerability in the restricted shell of Cisco ISE could allow an authenticated, local attacker to escape 
    the restricted shell and gain root privileges on the underlying operating system. (CVE-2023-20121)

  - A vulnerability in the restricted shell of Cisco ISE could allow an authenticated, local attacker to escape 
  the restricted shell and gain root privileges on the underlying operating system. (CVE-2023-20122)


Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-adeos-MLAyEcvk
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3aa66956");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwd07345");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwd07351");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCwd07345, CSCwd07351");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20122");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/08/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine_software");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2023 and is own  ed by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ise_detect.nbin");
  script_require_keys("Host/Cisco/ISE/version");

  exit(0);
}

include('ccf.inc');
include('cisco_ise_func.inc');

var product_info = cisco::get_product_info(name:'Cisco Identity Services Engine Software');

var vuln_ranges = [
  {'min_ver':'3.2', 'fix_ver':'3.2.0.542'}
];

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_WARNING,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCwd07345, CSCwd07351',
  'disable_caveat', TRUE,
  'fix'           , 'See vendor advisory'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  required_patch:'1'
);
