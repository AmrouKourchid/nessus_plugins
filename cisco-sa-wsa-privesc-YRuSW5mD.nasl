#TRUSTED 55fd396785c4b4f749eda03a037c806285b0a6ef1bd1b94483436b2a64bea385e1e32fc16adec4b13b0b93c1d8e64dbf0ae0cf9b9017316df52b1e4a1b618083007b56a673288837c6a20e4f71e49149dffd99f578219ce9214ab52004eb9175cf47d85f885e8eea2681c1b312f71fa1c5fbdaf9142d31b3b80afd249f002af1e85af7fd0a05910953bb5ecf6a9b7278d9bc796fd48144ef1d8d80ff6422b6064d55dd3dd06a1d4a5be8e0f3aea244e47eded124944bbeecdb1a3865857843e8a9edf7bd1f73bb8728f42d165816500c5376ee15a7f96ad9a58cbad4ae258351a7ae2422d3f87fb7a9b54fd69ab7fa9a7ea88a9d2e1dd356cc16b358bb0ab3958bf853531ed421bdfb44b31a973b15e68f5d200706f80bbf5a26b52f7d2f29fb45611a167c525db46336720e8902557efb4306e90f8928df04cee03f456a55571d5ff3b2f0361ca5810a803bee36f60eeefc6fa91badc9e51205b8ec4cccb59bb99daae0590f275ee2249d5e711a24d003f9436ba638c6e0de838d1589e62e37ef4318c2c4919c465cbb8354bd4070a462f0f7e79202645c575196a44e6c10b314a59e7266c057d18b5a5bae95f0fd1540a6cd6a8ffcf1c64abb36a0d0b4701a9a9972ca1eb784253411b13e6171edb79b7d190081e9a5e757312c66e49546ec529fe074cbd41b42f3a073a8ecfb1ae20be6380298937bad0ecf7a39bbc847fb
#TRUST-RSA-SHA256 7937c35df892f2890ddce80586ec9d92f56dc7baf8841551a839f73c6b67b5b301a1d8354fcba6475f2689fea794b9ce19a1e6e67d90e36b67caa8eeecb84955c3732f1888420c8f3bd97d69349da60420a830d74338faf336aadbbf24ad9b2ab4801aa9d1fd36cc3535229561c80e75f1152b4e1c49df32de6179a6c8bbef62f5af9a05a3f7404bbed47605ac3d267df6ff1aedeefc817fa615cc64c0d0d9f14821f74569c5446298c0caa34632c031b119cd100c16a2147764f4f9e012bb4adb0efc87e99c8c8e65f52be3e951e9143161abf618da7d569b3ba25284113760b22be6a573db570867b95f77572e7b87e5a00b89dd371317b97035675c934d8ffded6c4549de58a6880c9b0417f5f3a0e5130eb6527a686f446620584f2dd6d159ed61d2b593b472fcadf339b8675c213eb310e303c7eb7dcc0a0cd2ab763156e707fe5484e9ed2a79ddceeeb41629fdb4768eff9873b89dd157522908a17577fff4bfe2c05c00e4f13aa747fff8bc014a4c700e97f3fd8c18a561b7e7e3ef6502a5860b7a91b6eca4d65df1e48e28951a74e3a70f74358001592dd6c061b9dd29f1ee4abd16fb4278168dd306dc1433117c6d70d3fbdf827b1fd29a978cf46d861f42e3ced650be3ccb3b348f7b4e786414d4af0da2232033e7470cff9286e31c0899013c2988eeffbc00d43d1e4129e39271f55f04ec2e7fd6323843bfcf2e
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(166912);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/09/21");

  script_cve_id("CVE-2022-20868");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwc12184");
  script_xref(name:"CISCO-SA", value:"cisco-sa-esasmawsa-vulns-YRuSW5mD");
  script_xref(name:"IAVA", value:"2022-A-0463-S");

  script_name(english:"Cisco Secure Web Appliance Privilege Escalation (cisco-sa-esasmawsa-vulns-YRuSW5mD)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Secure Web Appliance is affected by a privilege escalation vulnerability
thathat could allow an authenticated, remote attacker to elevate privileges on an affected system. This vulnerability 
is due to the use of a hard-coded value to encrypt a token that is used for certain API calls. An attacker could exploit
this vulnerability by authenticating to an affected device and sending a crafted HTTP request.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-esasmawsa-vulns-YRuSW5mD
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?38dfc160");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwc12184");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCwc12185 and CSCwc12186");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20868");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/03");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:web_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:web_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:web_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:asyncos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_wsa_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Web Security Appliance/DisplayVersion", "Host/AsyncOS/Cisco Web Security Appliance/Version");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Web Security Appliance (WSA)');



var vuln_ranges = [
  {'min_ver' : '11.8', 'fix_ver' : '12.5.5'},
  {'min_ver' : '14.0', 'fix_ver' : '14.0.4'},
  {'min_ver' : '14.5', 'fix_ver' : '14.5.1'}
];

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_HOLE,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCwc12184',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
