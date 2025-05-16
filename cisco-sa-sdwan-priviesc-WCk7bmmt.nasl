#TRUSTED 35e23a531140dfcbf9a807afecc20bda8c4231d35129fa7f97a43092394aaa7d41ccb919504386ff6df45d890a9517118757dee30c5b057d75dd7e84f51b96457d5f2bb2fe9e9e708c8770c3db2d6400fcd51e5ed9f2121e8ca61bb8708951369d0e17425843f7c062022df412adafe0594b81033b58735572c19f5a986f710fe34c7a2555fbb672ed72d195c1632385c31e61ef50cbc8ecf4dc53384f2310b439b4ff23c874b8b5db230d0ede051837383fb5b43a39a0e21387cbac3b4568797c78341a5dd52ba8aeacf28657273cd0074dbaf9c352308f4574906c7cb66764b30da277fb01de21e49258d992745b4a97c2ebcf2cdf7c3f51b1e2d38cd693eca2cb0ccbdaa709da7883f95b0ac07cbc50e614c55bdb8483bbe0cc3f0f4e11a246929a13284950403214ea2e8492fff702a571a215edc7a683da0440b3ced4374fa09074ba777dbb977e2c485f75ba774c480efbb014d54a6f8e86220da199d073dcc150230e4da2c34c0497d01b61d517fb83342eb27ccef5ae66cdc3ea097fc3dbcfd35d29f0023175674ed389e6820fe456a4953a2ae22eadabce6e0b674f082fbc054d6a54cc3b1477af6ccaf83af972e64b953ebf3ee47af1231e9e39c232c4a676b0f88908c6bd2e88a9d1d5d54e961754bde78a3684fbf5381d95d9471db572a2e00e6cdc0c35df6b3f905267e8848fbc0ca0cc4c3ba94e430a087f44
#TRUST-RSA-SHA256 8f48043c8e3606978d8ea9b65954431a48034e6368d82147754b5b5102acf8b6edb148be96f962652676204fb968127631f94c908e13f50cdaab30314a1253c52188093f653163b330d26143aaa5bf7272bdee928bb98771e01935f9290fc31d6393aa1577149477122d2f74e094cb942bc82ac82d8f1fd966a617076c09b0fedb99b481fe1d300fad91538ef42f9471247bbbc776dd36539da1f6e14da712941233247f4e434430adf3f7e56fdf2e256a38a6f0f57f88ccc77f178d9cf01a372bea66e36ecd149adea044d684a89abe1824f9a4c12bd6586612c66321e3b3386efcdf5840ae91a0dc65acf1e433902ae924d911b2afafd9513de07702608e1b0dc16c246101641fe8cdf05d4adc51aaa85ce09d940653467c3559ad368dfb8accdf2ea09dbd316e79f660583918fd013dcf4494c3141aa7ae4d1d0720951ce6b931e4b88796cd632da26fb2a19b9b78f26346edebe6e0cde88ac92924085b3d98d504b11c75e485c18c0561aa6b1ef7cdfbb0e7fb589405a3123f0542822ddcc5c9975bf9e099342540859859a6d0749ead79d18c8204eb7f6830d8ee4af10aebeccd4d5b6fb1524ad69d9520711a680cc31bfb0a8f247dd8a3581e8fa8d03d3cd7a01efaa699ae11af3e557dc2a59988de4ff7d65e5c4d2ad5e53d0e985e44502dd3e3339a76f08e0abb67612828ce8e7bccbdc4b7a0693973bb854b540188
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(235483);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/09");

  script_cve_id("CVE-2025-20122");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwk92200");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sdwan-priviesc-WCk7bmmt");
  script_xref(name:"IAVA", value:"2025-A-0316");

  script_name(english:"Cisco Catalyst SD-WAN Manager Privilege Escalation (cisco-sa-sdwan-priviesc-WCk7bmmt)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN Viptela Software is affected by a vulnerability.

  - A vulnerability in the CLI of Cisco Catalyst SD-WAN Manager, formerly Cisco SD-WAN vManage, could allow an
    authenticated, local attacker to gain privileges of the root user on the underlying operating system. This
    vulnerability is due to insufficient input validation. An authenticated attacker with read-only privileges
    on the SD-WAN Manager system could exploit this vulnerability by sending a crafted request to the CLI of
    the SD-WAN Manager. A successful exploit could allow the attacker to gain root privileges on the
    underlying operating system. (CVE-2025-20122)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-priviesc-WCk7bmmt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?87ec9513");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwk92200");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwk92200");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-20122");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(300);

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/05/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/05/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/05/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_firmware");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_vedge_detect.nbin");
  script_require_keys("Cisco/Viptela/Version");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Viptela');


var vuln_ranges = [
  { 'min_ver' : '0.0', 'fix_ver' : '20.9.7' },
  { 'min_ver' : '20.10', 'fix_ver' : '20.12.5' },
  { 'min_ver' : '20.13', 'fix_ver' : '20.15.2' },
  { 'min_ver' : '20.16', 'fix_ver' : '20.16.1' }
];

 
var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'bug_id'   , 'CSCwk92200',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  vuln_ranges:vuln_ranges,
  reporting:reporting
);
