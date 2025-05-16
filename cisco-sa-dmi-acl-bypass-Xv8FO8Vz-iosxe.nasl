#TRUSTED 48b1e8de061139eb010d56786a0e50e70df50937615e12696761542eb082c3c18246c1c462c7ab22fc9d0e4c247d8efa42eec3a6864304b4bf09d61e33411282e9485f137be3daa14b53a7dd79850c83a68705291f50fd1a6a6c52095ee627ca5e5c3eb92c6431a4719053d1caa8857af7af32bc8cbae2d4a07d7955c48869ed5f208209037ad504384060355f0d5c8263f540d4fb9e982fe16abd557a95f9f6cb9f559000974f51b56619cf0dd7d4b23091a12de6e00e2c95ee0ec333a736d26a6687c371a6076a4a13d061367b96bb7d5d68fea69ae3c00d30b75e38996baff57d87d62f3f93b86999f8b3aa5ffb7ab6b63f6a9fd2fc2b8c2b75506f2cfe6c4d518cee5ce5e68bef122811b364fa8f935bdb7455114c680393cddc0b7bf4e26bf123b9db0551bba5e2c4c38a5134d3a30fd04a1bf3f68164784d295f44855910760815cc32706dc21ae293a387e0085dfbc4384c299c2806f642de643abd78166550537e9d0e30eecb2750d94f35eb2b4b57265c97362c0f12b1f58d9ea955435e63be4b9f85aa941305700d8b520d521554aec294b458df5fbac3f85131a6b3a01defc1f739fe88effcda4e2fa14d519dd3b02ea9e4dbbe6be1ef47b77851137b55eaa4267766d6bfb4869d29212e84efa62d5c2c49e20c017b24ab3808638b5aaf216236ced47b29b81d5c696be4c9bee6f05a2d2815146bd9f5c9e02017
#TRUST-RSA-SHA256 80d2ca0fa37fb24f75a8b01a8a7dfc7d1682aca8b6c3fb705c404b47e1438e1139da949f84e1e3f7e20175f9c6b1f3e7dc6593e39b04af76425080ffebb634e0125736e26665b04a863b747146198eb22bc1de429df54701f0431a24ec99241345e71018e9ab434acc21ffd6399397ceb56e80415b9226db460bb4e4e8f65d3558e40003d9498f9eac5229fc23d168c274f52121d266380b3d8bc494f1595fb52e595993b0a10f06dc48e1b2e6b88123ead98e7d1a6d96f8cdc21be414ef37942583c07f1ce248fd543241d8c4cbfb22b63f75685a50a0d944d891b400408d795cd9048be6257ec54a6c3856170df83905573b8bb1c6bb55e1321330e9366b694892343b722822c75e96a2af66a90f23f0dc0a2091f43181e73caf80ee86a2816cd76e9956275efb135ff4f8902460bd571c8606b5600af1239db2054cdf4c41d6f95bd4df3a88414595fbbe4be73a69cd4cc2a21d8a28cbf1936905bfb85d2f511f8267fc60e2154455cfe09df61b218c62d06a711189c5256d0c88b52a9ea02aa5f34ceffbf3b870c28673c499c87732ddc2ab12a21b80c64356c6bf8c060c3d56dc090696336d908f84e2ed06c07d5a91fa1f0369e212e24dc203303007651cc7e5a03665cec7c4977c64256704de552389ff01b05d9b47e48abeeae150b4ad6708f22a4664c902c8ffe90976406340dabbc8130f55237813f0437c0450ce
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(192655);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/27");

  script_cve_id("CVE-2024-20316");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe12169");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwf92391");
  script_xref(name:"CISCO-SA", value:"cisco-sa-dmi-acl-bypass-Xv8FO8Vz");
  script_xref(name:"IAVA", value:"2024-A-0188-S");

  script_name(english:"Cisco IOS XE Software NETCONF/RESTCONF IPv4 Access Control List Bypass (cisco-sa-dmi-acl-bypass-Xv8FO8Vz)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS-XE Software is affected by a vulnerability.

  - A vulnerability in the data model interface (DMI) services of Cisco IOS XE Software could allow an
    unauthenticated, remote attacker to access resources that should have been protected by a configured IPv4
    access control list (ACL). This vulnerability is due to improper handling of error conditions when a
    successfully authorized device administrator updates an IPv4 ACL using the NETCONF or RESTCONF protocol,
    and the update would reorder access control entries (ACEs) in the updated ACL. An attacker could exploit
    this vulnerability by accessing resources that should have been protected across an affected device.
    (CVE-2024-20316)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-dmi-acl-bypass-Xv8FO8Vz
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?af639aa5");
  # https://sec.cloudapps.cisco.com/security/center/viewErp.x?alertId=ERP-75056
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a1da659d");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwe12169");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwf92391");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCwe12169, CSCwf92391");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20316");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(390);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/03/28");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

var version_list=make_list(
  '16.3.1',
  '16.3.1a',
  '16.3.2',
  '16.3.3',
  '16.3.4',
  '16.3.5',
  '16.3.5b',
  '16.3.6',
  '16.3.7',
  '16.3.8',
  '16.3.9',
  '16.3.10',
  '16.3.11',
  '16.4.1',
  '16.4.2',
  '16.4.3',
  '16.5.1',
  '16.5.1a',
  '16.5.1b',
  '16.5.2',
  '16.5.3',
  '16.6.1',
  '16.6.2',
  '16.6.3',
  '16.6.4',
  '16.6.4a',
  '16.6.4s',
  '16.6.5',
  '16.6.5a',
  '16.6.5b',
  '16.6.6',
  '16.6.7',
  '16.6.7a',
  '16.6.8',
  '16.6.9',
  '16.6.10',
  '16.7.1',
  '16.7.2',
  '16.7.3',
  '16.8.1',
  '16.8.1a',
  '16.8.1b',
  '16.8.1c',
  '16.8.1s',
  '16.8.2',
  '16.8.3',
  '16.9.1',
  '16.9.1a',
  '16.9.1b',
  '16.9.1c',
  '16.9.1d',
  '16.9.1s',
  '16.9.2',
  '16.9.2a',
  '16.9.2s',
  '16.9.3',
  '16.9.3a',
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
  '16.10.1e',
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
  '16.12.2',
  '16.12.2a',
  '16.12.2s',
  '16.12.2t',
  '16.12.3',
  '16.12.3a',
  '16.12.3s',
  '16.12.4',
  '16.12.4a',
  '16.12.5',
  '16.12.5a',
  '16.12.5b',
  '16.12.6',
  '16.12.6a',
  '16.12.7',
  '16.12.8',
  '16.12.9',
  '16.12.10',
  '16.12.10a',
  '16.12.11',
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
  '17.3.2',
  '17.3.2a',
  '17.3.3',
  '17.3.3a',
  '17.3.4',
  '17.3.4a',
  '17.3.4b',
  '17.3.4c',
  '17.3.5',
  '17.3.5a',
  '17.3.5b',
  '17.3.6',
  '17.3.7',
  '17.3.8',
  '17.3.8a',
  '17.4.1',
  '17.4.1a',
  '17.4.1b',
  '17.4.1c',
  '17.4.2',
  '17.4.2a',
  '17.5.1',
  '17.5.1a',
  '17.5.1b',
  '17.5.1c',
  '17.6.1',
  '17.6.1a',
  '17.6.2',
  '17.6.3',
  '17.6.3a',
  '17.6.4',
  '17.6.5',
  '17.6.5a',
  '17.6.6',
  '17.6.6a',
  '17.7.1',
  '17.7.1a',
  '17.7.1b',
  '17.7.2',
  '17.8.1',
  '17.8.1a',
  '17.9.1',
  '17.9.1a',
  '17.9.2',
  '17.9.2a',
  '17.9.3',
  '17.9.3a',
  '17.9.4',
  '17.9.4a',
  '17.10.1',
  '17.10.1a',
  '17.10.1b',
  '17.11.1',
  '17.11.1a',
  '17.11.99SW',
  '17.12.1',
  '17.12.1a',
  '17.12.2',
  '17.12.2a'
);

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = [
  WORKAROUND_CONFIG['netconf'],
  WORKAROUND_CONFIG['netconf_or_restconf']
];

var reporting = make_array(
  'port'    , product_info['port'],
  'severity', SECURITY_WARNING,
  'version' , product_info['version'],
  'bug_id'  , 'CSCwe12169, CSCwf92391'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
