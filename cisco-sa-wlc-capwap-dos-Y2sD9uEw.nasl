#TRUSTED 210d5c29dc7d0739bd29c314e1ee2b7340116a4973bb8074d39b4467e1e3e11d3fdd3e615c075f973626436b4bc42b91db57c8dc4832172da2b3c423cb28ed38585b5767227592922433bdf55c195f0217e43aa0c5597928ca918de4cb180883c404456df154c61672fc40b47c77ad26b4aa1926521028cf1a97679142056b0e4a303cd222b2c6f5f1cacaecd3537290dbb353f4abe5d9ccd19d21dbe04fad7ee1f6d27c2b13bbfd6da8ad1d0dfa5b8d6ea43c1710d9b076ed6bc1fd81048125d7f67da63fad9a2ebb5782f8e4d093aa4d5b3979fcea962d5c8f5fa27736d1f585356799bb42081235cc1cfe119a56bc9b7be892fff047562ecc13b21d97d703966fdfa0de308d36aff80cec3858036e932acea0363a91c2c4a290da4a450d758aa80acf0d95cff3204b8e72614fabfe78963a20fbe2c3de76e9abc5b4d58cd82fdcbd06f4ac8ed92b971f5efaa8e1fa70b57e5076d3973bab4d2d1fea1a454c9faf76059a85a2cd06f44398c7d96808180934650754e2588774e99869a8c0f9a8508784698dc8015704037fcf4fa5871204aed4e9dfd029d22b4cc597e1db0df5fc248049518f6fd16d50cfd0dc4d8494139ed989b2be7c3e03a1a3c5fd0e7e143e46e8bbbfac03863fec97c0a3caa6e4381a0926a96292d98c2ff39111d0cdf9666e19510dae183dad3824cae060955b105589aaa7e5e2605460dc2048fb67
#TRUST-RSA-SHA256 49125f34934a53b6070b7a808315b051de8f361c1344a6ec13e8a323e02f9500f9443e945899a93e2b6f2a835756d7373e2870ab182e0822a0f9143039de92a24b63232537fdd29e03f9daa8e1aa1fe1ecfdd58f466a037a3d6be5a225602f3897dc49e6e17359dfe750aadfa5c645d6943f24ebc51e1fca01a9a8d426c636c2c6c22d92060011208020fe1563e04a9a4eed6c5c10c2df6d410bfe7507081070688d03fbb311000ed65a0db600bc55721ef566913b9d340d4dfc7e577da9cffca585f558b02eef4b670c7cea8c26e71604845e47c1c9fba48821cb0aa1db11167d94f5f9cb4f1458e5877887489ecbbac037cae27b92f610736f94347f5429906a421c817088adbda6ff2b8e0b7a1322fae63e618bd47a1c4cba16ffce62ce3847afc86457dbdaed5ecc0fa0a94d0f98bd57e618a6761bafe8b5483f22603c8f67f33e9e6903d72cfdfa891f1d56f2a665a36bf523bd6c71abd1d6f5366866ce5fa0618f78a2b3c0d3f61082a93250328128ef670908beea2a7f2a135f1ef11c01dda249e0461ffab7c09c899834ae244b3414f1f52b70f6e65ddfad44fe2c836b06bd9f693ec79a555cd74d0a788541b7dee9ff0b78e20c86ec22fb3aa1930ec19ca831f3afd667e9a0dfa74796f48d6c7f311566aaa2a1a9c4d28170ba61d5f50b8836d98dcd8acca6f1a73fa5866b3003c5896e7e6d7bb1e3f5a692e5de85
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(139036);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/14");

  script_cve_id("CVE-2020-3262");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq59667");
  script_xref(name:"CISCO-SA", value:"cisco-sa-wlc-capwap-dos-Y2sD9uEw");
  script_xref(name:"IAVA", value:"2019-A-0424-S");

  script_name(english:"Cisco Wireless LAN Controller CAPWAP DoS (cisco-sa-wlc-capwap-dos-Y2sD9uEw)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Control and Provisioning of Wireless Access Points (CAPWAP) protocol
handler of Cisco Wireless LAN Controller (WLC) is affected by a vulnerability due to insufficient validation of CAPWAP
packets. An unauthenticated, remote attacker can exploit this, by sending a malformed CAPWAP packet to an affected
device, in order to cause a denial of service (DoS).

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-wlc-capwap-dos-Y2sD9uEw
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?15aca64f");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-73978");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq59667");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvq59667");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3262");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/28");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:wireless_lan_controller_software");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:wireless_lan_controller");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_wlc_version.nasl");
  script_require_keys("Host/Cisco/WLC/Version", "Host/Cisco/WLC/Port");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Wireless LAN Controller (WLC)');

var vuln_ranges = [
                { 'min_ver' : '0.0', 'fix_ver' : '8.5.160.0'},
                { 'min_ver' : '8.6', 'fix_ver' : '8.8.130.0'},
                { 'min_ver' : '8.9', 'fix_ver' : '8.10.105.0'}
              ];

var reporting = make_array(
'port'     , product_info['port'],
'severity' , SECURITY_WARNING,
'version'  , product_info['version'],
'bug_id'   , 'CSCvq59667',
'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
