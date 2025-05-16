#TRUSTED 8e9352438609ec74d03f9f9ed8e88b036ab02daa22417c525cddd1a79335ee8d06682d1a63dd9487c70a384e4615e259a6a62c407c6af090b9b6115e982518d46187dc8d4e209c1f7ce4b555bf75004a1d0d2f4932b9acc2bd03980668d74a333135fea21ce89f1d50aa1c20d11b1a36498dc26449ed907fdbb123c02311b0b7003a1d26a0f296e6796b173154b1645380df1317c01532c9f4a4adf22f0ca498cdf4020b103aab404729e5847bbcbbb3a2f497917ddf40857b65bc171dfcee101456986f19017ef4e547d100a9695fe9aaf4df07c070ad17d25266cee6aa32c251c53c5a0fe0f0b4d3648492508123ac0a18f4c86f7186abb787e04602f5855fddbd3c442fb34a04dafb01bad10b1d0a3dc96bd75708f4dd0c54c83088ee57f863fff64ac26863bb8e0e2c63d75fa5c21e686fb114ad7b25454fe0f94176613a641be51650a22fc5292f0b906974a694784cf514e045d7daac7f0568f16df6b633d7f9141e1518fc457e0ba2f5f925479e869ae9d2f55fd23e92b64c394762e6921533f465e49a87e29877ce337cc0ed5f17dcf10c312b12bace33cffa8f307e24246084729a149f837be9cf674c14fbf7dbc417709c617f494e8a70f9e92a314ac4164d38aacc4bbad9aa054517c2cdd6e278c81474d205b337132d34b3be4a55e46022460f6ccd7da14eb4381193dad8518d8f3f1ff88c978dca12f609c455
#TRUST-RSA-SHA256 7ce094e9762173481401ab362d9c6bad931df33fe168a3bb27a44b08e74baf0faf54692021fa0a0640769e6894b818fa5d759b70762e9c933b2ffda22fbdda4c13cdd7f56ef269e4c06a593cbe8cc0cbcb368f2f11d672d56f9e0d75b7f8b1939b84cbe034e6c2ff5babc269e105c862593f072065f64a1b13fcc95a767592eb0a60c9838b1c7486b0a53e26b9731fd00064917bd5d3c95fa00751aeff4fb9da228a060dc4cbcaea56b273fae48e219167263e8440f39368ce4ceda8952e53ca2af5562368d189a0c06cc0d1878672331983b61e288e18e70d8f2cf2975c4f380955bd4851056b3352e39f43e29d0f5b1f0fe6dbba26c55a1680b76795e1d40fcdc73c007211cf4c01fc8cb2b946ff23b09366ed3d4e6ac6a1c6e550eff546044d9a78e763d950e2099d36ae6f92fff58a974061b33bebf7d3f7cac1208c4247349e8ec0e0b566a42e4d956f77ad2e17f5c4f663fcc6f17f1934c63bfa081c71de0402e3b8468ac986aaa57323b9f412c969548eef071c12ae9caa0a82826f2f8e887b0bafb621c9a013b15a930856365de2c54d59d30513a49a1b78133ead27eec29b9fc3ef17c6a9511d9e67615fdd6f5711c09e96f0c4e9b288b765d5194543de2a8eeb6433493416a487bcad2a14c6e538cd3c900b2aa1f88bf4b35b2c56ec598b631c0d81ff9f7574e5cc7739e05a78a20ba45ffb0d7a4822471f1d24e6
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(207742);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/04");

  script_cve_id("CVE-2024-20496");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwc99618");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwd85135");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sdw-vedos-KqFfhps3");
  script_xref(name:"IAVA", value:"2024-A-0601");

  script_name(english:"Cisco SD-WAN vEdge Software UDP Packet Validation DoS (cisco-sa-sdw-vedos-KqFfhps3)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN Viptela Software is affected by a vulnerability.

  - A vulnerability in the UDP packet validation code of Cisco SD-WAN vEdge Software could allow an
    unauthenticated, adjacent attacker to cause a denial of service (DoS) condition on an affected system.
    This vulnerability is due to incorrect handling of a specific type of malformed UDP packet. An attacker in
    a machine-in-the-middle position could exploit this vulnerability by sending crafted UDP packets to an
    affected device. A successful exploit could allow the attacker to cause the device to reboot, resulting in
    a DoS condition on the affected system. (CVE-2024-20496)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdw-vedos-KqFfhps3
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8f7093e1");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwc99618");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwd85135");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCwc99618, CSCwd85135");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:H/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20496");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(787);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_firmware");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:cisco:sd-wan_vedge");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:cisco:vedge_cloud_router");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_vedge_detect.nbin");
  script_require_keys("Cisco/Viptela/Version", "Cisco/Viptela/Model");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Viptela');

if (tolower(product_info['model']) !~ "vedge|vedge cloud")
  audit(AUDIT_HOST_NOT, 'an affected model');

var vuln_ranges = [
  { 'min_ver' : '0.0', 'fix_ver' : '20.6.6' },
  { 'min_ver' : '20.7', 'fix_ver' : '20.9.4' }
];

 
var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'bug_id'   , 'CSCwc99618, CSCwd85135',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  vuln_ranges:vuln_ranges,
  reporting:reporting
);
