#TRUSTED 1f993af92b3a411506e5ef5ad32b647ac02e901481b75ff9aaea42575c0753faf1557c47da11803694f39b16f5f0dd8504228df19542d3d3ccbfa4f24787f66a3f46ca54934e00f5114ea60e1dc061585339260a01c43ce0fd212127947175a66e8a2e6d9c400c021d7024242f65a21f88f9ffd6464e9815863b9b65f3c76b0a85056e6a1a66defd10299a02e733393765faa08f4c0c045ed1a45a2c107ca23824f1585535d8358e925cb3dd991e017850f831265803c393f200866da740f6dc4c2fd7e3a65b211bb834b5d314c100797307af5b51ae5710318e52ebf781679ddbb591f64515c07154d4ff9311c667df61a005d6ffc11aa60fb1908ab39236654f5411f95a9f36bf59094bfe26bf33763bb668b98c55b993408935bdb0ef58e60b968fbdc0fe95fb602cd81b122776cc9e464a09fc84e4acc9343da149ae359a19d8b0149abf88afc2f40a882df7e65d8ae1c71cbf6efdf88210ad7ac6436cad4e398f1443b991bd0e5f18ad6c168bf82b42efc31913a8ea061951a18f5412306922dbc5b231b9f88d5fec6dc9b4ed06111c55761c59855311176289f9ab414cf02c0f7e82aab418b80c174e94ca929a5f8dd1f82ecbe366a68cdf3a1db00b81f1ade0c0ddb07ce60ec4dfbd2a3ae8a404fec0d0f4ed41a9cec7193690c30d274259342a483f924f0f53b21f20b343053229867e703318e86ae394fe51072477
#TRUST-RSA-SHA256 8a5a8e01c1fb9be0a3802dc0e1cd04618267af20bb03fcd1174cc4304314f12a74430e5ffaf63b2968e4b466fc8f26138b21dc4826147313e8a6bde90a3f752fb8957461f85103fd2c51b76856f226ae951765fbb5212821b1ac3dcb39557216d9b605caa302a97b2e3351d1c0ec7e3487f3a49bd898dc26db74c75de31b8ba6f0adcb40275414b2e19e4b143e61cb5861df8607d7636a404b58a20a77b58cd2738c776ecd5595247e51e6efef319b6909574fb087f11ba645a4824b7b454fa314a41be23eef5720ff9a98e783c6dd7ec2a912cf35b0b41282359966b44fb55f5e30f6a00bfe0d5d834442a2b4160adddd11f9e1a4a1d44c76f3cda235261d6009e2e86185041128b9b5095ed18fa4921da8b1af945f3e962c2b960d08b5c58d8f777f2e5d6e2c6641147db5af667968b7d722b3b5fcaddcda4433c0bf28dd4cf9d47c617900482553f2c1e54e459503246d3f32fcf16eb7cab01aad007c49b6211911d609e11945fdbe93bd157d2ed962c08c26c1494f88c06f4cc0ff220dcbd17ab317cafe6b6aef88ae678d13229612bc1a1f9bc70d9d6f5f9292cfa0a1e1bba10c023c0536b697d04200cb15bf53d56af7638d8816862e87fcd938f65226f5a1ca2c6b16180ce5f7eb5c4540d37fc4bb4b59da8d045cdb28ae5104b13e51594d5f47d695ca04be50bd2b532df9af31f5e5f70d06a23dd9008a24ebfc9123
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(131729);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2018-0195");
  script_bugtraq_id(103557);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuz56428");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180328-rest");

  script_name(english:"Cisco IOS XE Software REST API Authorization Bypass (cisco-sa-20180328-rest)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by an authorization bypass vulnerability in
the REST API due to insufficient authorization checks for requests that are sent to the REST API of the affected
software. An authenticated, remote attacker can exploit this, by sending a malicious request via the REST API, in order
to selectively bypass authorization checks for the REST API and use the API to perform privileged actions on an affected
device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180328-rest
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e53dbd21");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuz56428");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s) CSCuz56428.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0195");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/06");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Settings/ParanoidReport");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');
include('audit.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

vuln_ranges = [{ 'min_ver' : '16.1', 'fix_ver' : '16.2.2' }];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCuz56428'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
