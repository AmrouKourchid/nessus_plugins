#TRUSTED 352da531da7f6aaa26f9210376b94be05af8c479c18d899501894ee876a6aac7f0acd9a1c4507bee291b08acdb84d8fe7068640b95f12453cf10bda94b33deb2b9aeac31afef47f38b5c4d019e6fc1abd414815f78564aaca127d4d4c0411406facb596df35279b6245ec9acccc7696dbb6a706eb349c77196cacc96b958bbc42d82f30e8c107a987aa0aba0adf60e1cbc422ba0a75579b9761a4fd05a7c58c6393f141aa1e4ee898337ede33ac7dd5474ff13193a14873c5e17f784564987132ad7e8a931a67de941399425d0527a18166e031ea0674054bffaaae1ab1c324cbfb40e1544ece8e00676ff4b576fb6fbe5f09fb48e3f3058cabb8af700382740f0f88f122559f67f16129c219185004a24ff77d6cd67bf8e8df69b56447aa61ee27f72f19e4dd08a32ea206f0d1dff75865b4718314e114d7feb7d2ef26b6b8c9c53a1c6e92aa06ce95d94be81a57c6880803d071cde7421e232f2c7874baef6063b2633405dcbbc59172782c9a97eaee60a4ff0e263d5eec8fc9ddc84018a458d82e0d1744554fe4fd7efbffd256f2ebad92e8d92a65c666a9661f602c64eeeac434c13f890cab2c6268de5421bffcc89859e77f4ec9fdd9ddc2a8b1b6310a3904c63442274838b76dd0af7bb7290ea70bf2e3fca4130d3d98481e17390e2d428fdd5c680f80a7019df2fbc7085756b74e2f9ee922e889af3a326bf623b385e
#TRUST-RSA-SHA256 91228bed92cadf5364568e7df809c49fb14c05415dd243e99206daf656975c0bab0987fb7127354924393679b714a18f1a752e82c6e0f8727f1da7c8b8b9460ccba14cc387e9de3c0a09e2debaaffeff34c456fff60d403d9683dea50e6db65412c0996eaeb842f99e781d6f4068fd1bc859a3c57803a131cce5d3730badfaa271405b94a0f641e9f5282e2350995e60cf5b11d23d744c65bf779a2dfaba90f7ed51527f46788844227be92ece21f3fa59f9b8718b5f5dcfa25e09c4cb8cb63426b96e92345d54c722d17394d55fb61f67d99f9fd8cc9b6546c10679b7de98ca3a47a39d3d46a98d4b593c192c7f89b54520950dccc834bbd2f5656b35c99d21039d657bb887949e2cbdacd96c2b5137822700f2d58fcfb9b1d2b36862c3e53ce8b9d7dfa4c630d21013776810fa8921cab6ab23264cd280254aed9466bb484bf73151209a23022de64a9939b4aec9107e62945972fedbe6d78d054eb495a587b1e46356bf7ed6aa23ad500f2c3416610f60182a410cad3c016fc0aa79a4c5c96b0f07716e274cd5d1d66a293ee1b6f0bdd45be45282454a2a1bdfd49596e86eb679ad46b14b9661e4f53145ecd415880047de0070741f86d2adf48fe8073ed7cc796efd1ca8de2f36239bb9db07636268ef040e8725f508214619f3879465487d0ffbaf968c15492c598075dff194acf756c1af356b86f1a6184c278355f12a
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(184456);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/06");

  script_cve_id("CVE-2023-20071");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwb69096");
  script_xref(name:"CISCO-SA", value:"cisco-sa-snort-ftd-zXYtnjOM");
  script_xref(name:"IAVA", value:"2023-A-0596");

  script_name(english:"Multiple Cisco Products Snort FTP Inspection Bypass (cisco-sa-snort-ftd-zXYtnjOM) (CSCwb69096)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco FTD Software is affected by a vulnerability.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-snort-ftd-zXYtnjOM
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ab2357d1");
  # https://sec.cloudapps.cisco.com/security/center/viewErp.x?alertId=ERP-74985
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9c46133c");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwb69096");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCwb69096");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20071");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/11/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/11/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');

var vuln_ranges = [
  {'min_ver': '6.7', 'fix_ver': '7.0.5'},
  {'min_ver': '7.1', 'fix_ver': '7.1.0.3'},
  {'min_ver': '7.2', 'fix_ver': '7.2.1'}
];

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = WORKAROUND_CONFIG['utd_enabled'];

var reporting = make_array(
  'port'    , 0,
  'severity', SECURITY_WARNING,
  'version' , product_info['version'],
  'bug_id'  , 'CSCwb69096'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
