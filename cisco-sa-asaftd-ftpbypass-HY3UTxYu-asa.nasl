#TRUSTED 0757548baa06cbaed67a13ada73700c715f1e99373a6d5238194f792046aceedddc528861a3377204577db23047011afd12851087e1e2a50092862c6722e591696a0230d35b89507d78584aa644ad4529309aae10fd75013cdd16843dd603496110e8a2231208c833ecb9dd6aafe405527ceaaac11a56b64c586f52e8e78b0e6d69499faa3c37411279f3827fcdd536bd4765a7a985920fd56bd20f7db2cbcd95574327ad82fa9c9d6a4a4ecac0569db3fd74fd56fc6a900030ab612aec6aacd3d6dc88796bb6e887d56f2e95aa8c7d21cd595ac23306bbc4714b71368027a9fd058f4dc0265c99b84d5f1c04337ed1218c1a0aebbce7474bccfe5ad9e1d29234bb02ccf01dfeea46c155437fde55a0fb8df1b0859c4055327f6cdaf536d69860317cb1f8779dbc3ee5ca4482665f9d2771c0ad907181b070f2604acaadfa73ba244e8b03dc768bbae7528a9b2ec61d48939468d583b486a1b9a8aa949d4ce17ee483d5e43a1ae8fcdbf867c170da5cbe6e0a81bd06533d32b510acb0cf3b204faa14ab47cdcae9562428ff3fd18c17a79abf5f636bd9de9b13212ce3e9678ef93b46ccdf88eb16558a38263d900c6b4c67c424d4629e3a6e4f605c61bc5ca5c42c7a4b37ce3ca3093bb8ec0ab1efada161782344f8a0e574cdc6da8af85fa1649b8ababc480fbff8c7c8a55fd023dd867a3f6a6be6dd8cb938aa36ad328b873
#TRUST-RSA-SHA256 429fd78cd773111369667e85430c410c1d10b00e003384348138d8df337b4917e091c43abe10e80c4f2b6e494c0b7677fc1594f508dd915bcf67d1af9e5367f8afc8cd4957dc3c0808ba0a0040b452e1cc2191b843b50b5b4bb0c113d8f66c55d0f9d93d126f7f5c7222bae9abcc24a09f496d212ef74770d94de1f2c5aa009cb1a96f6ead413f4653a00901ed4dd0d03b6f1a78ab59632669de3cd5cb17f9beb8aa3a8cb12d593ebc2afc7055675d9f5a732884fae164c280bcb9c7777752eb4c8bd068270cefc71a9f96304a849aa759434ef55801a027d8e6b0a86a188e467f71f1f791c0324cbbe75a3e08bd3d2f359e81873d818a74c89ea7375acbfc39223acc9074151ffa942a6ee1dc9d3923402992c40fd19e7244e11b9949529ca615e385a664d6a67ec1124a625b98d726b5bcc45cde2630e808c6b04e256e23951ac56da2fb7dd4fdd9299b8c913eab02b8ae04473176349c69475b040dbed1890d7b11ad4fe1e5c92d3be6ebc9c4e32a3aa9ba5983ff8a2df0a0f1f4586accbdd81b8753d342a94fd0809c46af12210d2743ad94743073663e8dd531574652e0751356a9e4034068b7e5a3b4f17f7385f6aa79eb6331940cfa2f7f6bf33529819288172787caff51589e0683e49364152087a1445b5abfee59d2df58a93e2c296b97069b85e3a28d772d287b22bf6ca0d4be8d1bf30317d7492a9e2ced2380bb
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(164350);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/26");

  script_cve_id("CVE-2020-3564");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt13445");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asaftd-ftpbypass-HY3UTxYu");
  script_xref(name:"IAVA", value:"2020-A-0488-S");

  script_name(english:"Cisco Adaptive Security Appliance (ASA) Software FTP Inspection Bypass Vulnerability (cisco-sa-asaftd-ftpbypass-HY3UTxYu)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch (cisco-sa-asaftd-ftpbypass-HY3UTxYu)");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, there is a vulnerability in the FTP inspection engine of Cisco Adaptive
Security Appliance (ASA) Software that could allow an unauthenticated, remote attacker to bypass FTP inspection. The 
vulnerability is due to ineffective flow tracking of FTP traffic. An attacker could exploit this vulnerability by 
sending crafted FTP traffic through an affected device. A successful exploit could allow the attacker to bypass FTP 
inspection and successfully complete FTP connections.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported 
version number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-ftpbypass-HY3UTxYu
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bf58e222");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt13445");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvt13445");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3564");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(284);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/23");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:adaptive_security_appliance_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/ASA");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco Adaptive Security Appliance (ASA) Software');

var vuln_ranges = [
  {'min_ver': '0.0', 'fix_ver': '9.8.4.26'},
  {'min_ver': '9.9', 'fix_ver': '9.9.2.80'},
  {'min_ver': '9.10', 'fix_ver': '9.10.1.44'},
  {'min_ver': '9.12', 'fix_ver': '9.12.4.2'},
  {'min_ver': '9.13', 'fix_ver': '9.13.1.13'},
  {'min_ver': '9.14', 'fix_ver': '9.14.1.19'}
];  

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = [
  WORKAROUND_CONFIG['inspect_ftp_strict'],
  {'require_all_generic_workarounds': TRUE}
];  

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvt13445',
  'cmds' , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
