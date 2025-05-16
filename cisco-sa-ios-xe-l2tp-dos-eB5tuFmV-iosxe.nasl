#TRUSTED 9be492fc3da5db469476cdf188582825695f07fcf9663ddb57533709df3168dd3d84b557d437c20963063f4fb59d76d4566acf951744d02ae36e8e5ac38439d84114e658ca509aeeb723ac1d9416066a17676b77f1de9beecbad254875c62ca61805a2f118491f7e6460f7dbd1f5983819ba6bfabb5051f118e109812a8c3806cff055b10c404b8f2b5c865a5275ce95aded2563f310a4cb008db45ab3f0037672cc690f5d2c83d8f2dcb4892163b47df6957a66b89f606c74127dc000fb65c105c0b3ac340b38c0c358fae67cca0b0d674e7f015c65245a30023930a018b6b8bac17f4048c395a0c45bc9266f653ae1b70d700bf09a80d997023e9f958955cf6a9dec44329c951b3cd5709cdd3f79d62875e10f1df917530791168cc4157e6314942c9be450122dbd6bbc94886a3d3be3bacf2ad982a250810c19cf50b7120816a409e02213a70aa0b21ad5e61045df62475b17472944f19a97aca2e7b4ea3e9e0f680d7bb6c7e3f224179b84f294fe2986fb3050e84f68142807dad36f8c35fce1a90e525a713f009b5d52b10f3c99c07469201300423707d7a5eae3c58af672196bc3607a0542af45982d9599682162b255e8eb4289f2109b115354f56f3ee98c34e3e74fc299c89fef0bbf2ed8f4a0c3ef1ca532b9e66a70ca06027cd7edecc3275b2a6829aacf8d375eb92a49e5fe252053b2d878de0c732f4471357838
#TRUST-RSA-SHA256 4fe253f2ab518fe90348d93334cb1e3611bdd03cade6a9c9732be2c566e168a487ec12e2ddb3b691dd93d67f0e597074325e012543f90c6ad7afa65dcfeb36859c6498e182d3a93ec4e11c5a4f2c0ec1162c72d9196e6d7ea09ded36bafddd2dff67f47ae0f97dbcdf65fa73e6cb6f8a6fa38f6f26154b14ef094632ed3730ace20991943f20ab9e8e54eee857dfd969d45f299758dcd3c535c1a51abb0ca50dc707c84fcde718b120221676201e23440904122a949407363b461e8e8eed9336adced3b67eb09450c13d16e957fe90802efa49666a8dbc711f59dbc60fbf05788a2f3ba27d558dde3d8c98e0ad921b25c7f198d47faf75206687aaad4932627ca5ae258cb2430dc653caf59a8c0188c68236e8102d964045b1dcc887b61c0c0750365fef2a2dfebffa16742da5aca3f54a6bf51a9c15068a1a6b5b69bdeccd1678740a3c5aea27e2fdb5b68791709815487b8e0bd82aa6b564e2a4810d2e61ba4d5f08baf669226c4e5b51fbb6a5b5db674d81dffd8dbe6349ce9a43f3fb36949975f85432a93a327a8964d43a5f969e3c0a50a7190e90616f8635a057fbe34311aa79ee6536a860c04a196a112c23898853d8bc9cc7abe9a5bad23bb652dd119ae92ddaf636e0763a8444802e120ac9e179d29e8f4776c2c03388b178df682bbcad14dfbe7c353eaf10fd5d34096812c30ad505f7b7972a7e1058ae7c0a615f
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(189764);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/31");

  script_cve_id("CVE-2023-20227");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe70596");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ios-xe-l2tp-dos-eB5tuFmV");

  script_name(english:"Cisco IOS XE Software Layer 2 Tunneling Protocol DoS (cisco-sa-ios-xe-l2tp-dos-eB5tuFmV)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS-XE Software is affected by a vulnerability.

  - A vulnerability in the Layer 2 Tunneling Protocol (L2TP) feature of Cisco IOS XE Software could allow an
    unauthenticated, remote attacker to cause a denial of service (DoS) condition on an affected device. This
    vulnerability is due to improper handling of certain L2TP packets. An attacker could exploit this
    vulnerability by sending crafted L2TP packets to an affected device. A successful exploit could allow the
    attacker to cause the device to reload unexpectedly, resulting in a DoS condition. Note: Only traffic
    directed to the affected system can be used to exploit this vulnerability. (CVE-2023-20227)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ios-xe-l2tp-dos-eB5tuFmV
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a20fa066");
  # https://sec.cloudapps.cisco.com/security/center/viewErp.x?alertId=ERP-74916
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f3520ae2");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwe70596");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwe70596");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20227");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/09/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/09/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/30");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/IOS-XE/Model");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

var model = toupper(product_info.model);

# Vulnerable model list
if ((model !~ "IS?R" || model !~ "1[0-9]+|1100|4[0-9]+") &&
    ('CATALYST' >!< model || model !~ "8[0-9]+V|8200|8300|8500L"))
    audit(AUDIT_DEVICE_NOT_VULN, model);

var version_list=make_list(
  '16.8.1',
  '16.8.1a',
  '16.8.1b',
  '16.8.1c',
  '16.8.1d',
  '16.8.1e',
  '16.8.1s',
  '16.8.2',
  '16.8.3',
  '16.9.1',
  '16.9.1a',
  '16.9.1b',
  '16.9.1c',
  '16.9.1s',
  '16.9.2',
  '16.9.2a',
  '16.9.2s',
  '16.9.3',
  '16.9.3h',
  '16.9.3s',
  '16.9.4',
  '16.9.4c',
  '16.9.5',
  '16.9.5f',
  '16.9.6',
  '16.9.7',
  '16.9.8',
  '16.9.8a',
  '16.9.8b',
  '16.9.8c',
  '16.10.1',
  '16.10.1a',
  '16.10.1b',
  '16.10.1c',
  '16.10.1d',
  '16.10.1e',
  '16.10.1f',
  '16.10.1g',
  '16.10.1s',
  '16.10.2',
  '16.10.3',
  '16.11.1',
  '16.11.1a',
  '16.11.1b',
  '16.11.1c',
  '16.11.1s',
  '16.11.2',
  '16.12.1',
  '16.12.1a',
  '16.12.1c',
  '16.12.1s',
  '16.12.1t',
  '16.12.1w',
  '16.12.1x',
  '16.12.1y',
  '16.12.1z',
  '16.12.1z1',
  '16.12.1z2',
  '16.12.2',
  '16.12.2a',
  '16.12.2s',
  '16.12.2t',
  '16.12.3',
  '16.12.3s',
  '16.12.4',
  '16.12.4a',
  '16.12.5',
  '16.12.5a',
  '16.12.6',
  '16.12.6a',
  '16.12.7',
  '16.12.8',
  '17.1.1',
  '17.1.1a',
  '17.1.1s',
  '17.1.1t',
  '17.1.2',
  '17.1.3',
  '17.2.1',
  '17.2.1a',
  '17.2.1r',
  '17.2.1v',
  '17.2.2',
  '17.2.3',
  '17.3.1',
  '17.3.1a',
  '17.3.1w',
  '17.3.1x',
  '17.3.1z',
  '17.3.2',
  '17.3.2a',
  '17.3.3',
  '17.3.4',
  '17.3.4a',
  '17.3.4c',
  '17.3.5',
  '17.3.5a',
  '17.3.5b',
  '17.3.6',
  '17.3.7',
  '17.4.1',
  '17.4.1a',
  '17.4.1b',
  '17.4.2',
  '17.4.2a',
  '17.5.1',
  '17.5.1a',
  '17.5.1b',
  '17.5.1c'
);

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = WORKAROUND_CONFIG['l2tp_tunnel'];

var reporting = make_array(
  'port'    , product_info['port'],
  'severity', SECURITY_HOLE,
  'version' , product_info['version'],
  'bug_id'  , 'CSCwe70596',
  'cmds'     , ['show l2tp tunnel']
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
