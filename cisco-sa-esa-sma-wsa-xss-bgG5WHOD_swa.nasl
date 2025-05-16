#TRUSTED 452ddd6d45917fb3cb8276c28daaf4cb5f79116c516890d9d02ffbb1fe13e519855116d72d1c643e41eef3f27e848f82a2eef73199b7d6f6592937fab9e330b2e55d22f9bffb65e40685f7e29a157f008c71d182022dd7c5c6db8a3e9e5914a36784321dbf45b02dfe410d11abe35d3c71361c3d423c62028643a6592cb608328f54457af13f6e0af95e691d73fa738a6eba8bbeeac50901bb1a17a2dcd09856725607279a975a10bdd65d8ece803511d0118fe29194193d3f2e6849107b52e1a5afeebd6b1a1f3f51904a526b50a06485c556b34ca6d35de479e7599ef0a14e6e6df5cfb1852e7df1e3225ead68cb16a84aa820dd7bda358f42041c431d675f78313482112f32b56381f6cde913ca51a743031861355ec069df0b0522ad356a4b2744c2b447c835cd0581d38498659f9ec5b3ed57b97105dd46b445b928b0344714d1fda011787f7188c05725974804d6ac732e4f086a8329e1851717d6ddc411a909afbf50cd3ace95f2ac7724979423acbd500e0fa9b2b8d6931058d9010d6ab7b3d0b8457ee51a8e24df940f27df72aaae101b80c9b2ef72e9c415b84a539909224ec503bddd638ed5e861657d07673ec5fceee32793ede6ce8e8b5fca16b129dd3b3399fb87ece7d3fcc7464a8912da8046bb5d8bb3251c8cbd27ea15abdcc67d27d19d445051f46bedd74b39c7adeffd7311367c55e7de8b5714f8036e
#TRUST-RSA-SHA256 4ad28ee609e8bf5ac90d4db5d8bb3706aa4c675eb740aaa0ca2b772e62529a9efb23a16aea327ac2410cc79412b53ba4a049124e1a9f5b7242bcd219f3b87ebf4c85bf53485b5d4a23305504895424e4d34ed01187c8b36f9fbfbd8d0e46339b9474016022d32cdbc9dc8010ac7141eb77faf09ad57ed801141eaaf2b79a8b68a49cc7aa13fbec085cf08af6e64d1b7e06de943a38a678be50f65c9de95fba7557dffce1ac07703b32888c3e053fb4553efbea6cb17be95be6f80e6d07c95456524507a24d9ee88d0e3d60bdfdd4224ded3bbfd2724d4e0af0d88109623a87aa5f114d6d73e9102a7375b247e24134d21dcf4454da91c431e0046bf02fb46dab13d0e2b5e39ca97901895d299304384599f1cfe0de7ddb1bc3ff8aff1fd64a0f8db2ad72f22377b36ab2cce6ffd314f5fec02a6888862129369e60a4a609d9ed2e7eee1f9309dc671660b90d4a06083a18c4bea30695e6ee93fdaebf90a899cca3c7af00dd45c6d352a59a46bfe0d4c1a7e1650fd8c88b1c5bd00d81c970f4117a3560ec99262399e97fbcc432d320b289f0dd34d1d41014182e712abbaeec19988994c7cf637e93b5b0ae760a78073eabefa34ce84ecfa5b2e17521c55db779874a2cec9df2d0cbfe260d8014bd9422286f05b7e51bc5ad608db60a5db8bd8fb15521819ce2585528fac0149d761703620426dc1717e54d511ad0bd7fb81c67
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(197881);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/08");

  script_cve_id("CVE-2024-20256");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe88788");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe91887");
  script_xref(name:"CISCO-SA", value:"cisco-sa-esa-sma-wsa-xss-bgG5WHOD");
  script_xref(name:"IAVA", value:"2024-A-0294-S");

  script_name(english:"Cisco Secure Web Appliance XSS (cisco-sa-esa-sma-wsa-xss-bgG5WHOD)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the web-based management interface of Cisco AsyncOS Software for Cisco Secure Web Appliance could 
allow an authenticated, remote attacker to conduct an XSS attack against a user of the interface. This vulnerability 
is due to insufficient validation of user input. An attacker could exploit this vulnerability by persuading a user of 
an affected interface to click a crafted link. A successful exploit could allow the attacker to execute arbitrary 
script code in the context of the affected interface or access sensitive, browser-based information.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-esa-sma-wsa-xss-bgG5WHOD
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?eaf46cc2");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwe88788");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwe91887");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCwe88788 and CSCwe91887");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:M/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20256");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/24");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:web_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:web_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:web_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:asyncos");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_wsa_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Web Security Appliance/DisplayVersion", "Host/AsyncOS/Cisco Web Security Appliance/Version");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Web Security Appliance (WSA)');
var fix = '';

if (product_info.version =~ "^([0-9]\.)|(1[0-3]\.)|(14\.0)")
{
  var vuln_ranges = [ { 'min_ver' : '0.0', 'fix_ver' : '14.5.2.011'} ];
  fix = '14.5.2-011';
}
else if (product_info.version =~ "^14\.5")
{
  var vuln_ranges = [ { 'min_ver' : '14.5', 'fix_ver' : '14.5.2.011'} ];
  fix = '14.5.2-011';
}
else if (product_info.version  =~ "^15\.0")
{
  var vuln_ranges = [ { 'min_ver' : '15.0','fix_ver' : '15.0.0.355'} ];
  fix = '15.0.0-355';
}
else
  audit(AUDIT_HOST_NOT, 'affected');

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_WARNING,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCwe88788, CSCwe91887',
  'flags'         , {'xss':TRUE},
  'fix'           , fix,
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
