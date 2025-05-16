#TRUSTED 91924e5c97ba7599cb3bd9b01e14cd55d183c5a3a5f556ecd4a4179833d554afea3abf37787d430b2531a7c1a0b4d5eeaef570cdb33ba205809c8673b843be19d23f2571f5cdf3b34dd30a814c51b90a3f32db2e0db7cfd84dbbe2b5ce59b5b2b06e98d0f6a5a8bf3547504e344948fdfda9d7c06bc99df2ee1eed015f158820e69c3e34b69d3d9e64d124b5a6728374f32a42ffa5a6dc68a1b311f25541845f98609071d2c22ad372a4bbc278ddd18a02ab63507377793248a85efd3fc925fad38936d715de7283de98d299909daa38fcd9ebc517068e5f5043322b84e585f4ac8a4e2cb616eb29b868f23272ba0958424d83b5aa23b045902bf7724b382c0a31f9dbd5f1196e4c34f719b44f0f423e5841cd28726b3e98733d568e098689a91bdc14e78b66ce437569a67e0e3c9b2c3a0798bcae91abb4b1765e1856deaedda59c1811dd05b1dcfb0e405373385219ada1f730152662b052442a77fc870f7b2f2d0c16f374774c32d20fc906c3b646db4938b8d7b10bc8375da4fa7f27c52d9132093ee3ed77a7466b223c1882d6822a89068e88499acbc360bda75ce90ace03a95f0a0c5ee37bdf58ec9a37d7bc66c1ee279e988400dd894f50c94a1204c33e32dd5a619827f777b3acf1924821a8b5aa827315d07a243844c156c238e43c83c1c0961e26fca06779f14e25d1a8b999b326cf5586968f5eb3e3eaa81ebad4
#TRUST-RSA-SHA256 5d2fa3d76425d84a143e29820e551bb60f3bf8081e34ac8b6ae0c47465cb123a4e992aeaae239748326eda6968d8752cb231d210b9d15038ad50cfc6b2c891522c66b4409df6b512478bfb5fbeed777ef2b54e7eebfd6858a1967aabde6365be7bc47600fa14e8893213d573cf1d04a58cd6019cf6c4a085c4e9811e4f1e321b64d197392784cccf52eb1fc9e7b020b70b388630b48a1cef3cba0dc57129c5ceae5552829b3120872ef6d2c7756736b264fb7b443ba2eb5fb835c1f3969c5ea0cdfc5f7dfd6629f232512487916be961b9fda9f410d19d1966806b6efbfeb1d3eb6bb800a112a93f12521440fdaad5b5b1e0ad29431fc3537b7d505fbbeb5af7105f1156c511ec758241718fa21967023d7bd35e28b9eb3f72eb7cdc17cc30e5ace70676e2fc5723e7ba3eba0131bb27bbf8ee7d86e93e7134237ef5658b595424655ba8e8a9a1c331d183a573ddcc18692cc799fe83ebca633da397bef26cd8f7fed19ba9fe4760b7009b18dfcac0e342187c57d26e0ee1e4a9852b6dec44af7870f08009d5a96cd225236ca47b497c8495f4eb5d5baa6c927a426263821db294aed43de3771843efa83270c2abda03c09c393ab98d94e8c7009c7c048e544413f1d2667586c34bc46bffa05f19fb4637af8197f0558d7771550bc88247fe3f36550c9eda2e8c65d980b7ebe9bd6dcd72f79d3d4804de3fd7b3630ae9f33af5
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(132697);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/21");

  script_cve_id("CVE-2018-0189");
  script_bugtraq_id(103548);
  script_xref(name:"CISCO-BUG-ID", value:"CSCva91655");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180328-FIB-dos");

  script_name(english:"Cisco IOS Forwarding Information Base DoS (cisco-sa-20180328-FIB-dos)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS is affected by a denial of service (DoS) vulnerability in the
Forwarding Information Base code due to a limitation in the way the FIB is internally representing recursive routes. An
unauthenticated, network attacker can exploit this, by injecting routes into the routing protocol that have a specific
recursive pattern, provided that the attacker is in a position on the network that provides the ability to inject a
number of recursive routs with a specific pattern. An exploit allows the attacker to cause an affected device to
reload, creating a DoS condition.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180328-FIB-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9af64740");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCva91655");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s) CSCva91655.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0189");
  script_set_attribute(attribute:"cvss3_score_rationale", value:"Scoring adjustsed to align with CVSS 3.1 attack complexity guidance.");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/08");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version", "Settings/ParanoidReport");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');
include('audit.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

product_info = cisco::get_product_info(name:'Cisco IOS');

# Some further information on versions can be found here:
# https://community.cisco.com/t5/cisco-bug-discussions/cscva91655-cisco-ios-and-ios-xe-software-forwarding-information/m-p/3371988/highlight/false#M7119
if ('E' >< product_info['version'])
{
  vuln_ranges = [
    {'min_ver' : '15.2',  'fix_ver' : '15.2(1)E1'},
    {'min_ver' : '15.2(2)',  'fix_ver' : '15.2(2)E1'},
    {'min_ver' : '15.2(3)',  'fix_ver' : '15.2(4)E5'},
    {'min_ver' : '15.2(5)',  'fix_ver' : '15.2(5)E1'},
  ];
}
else if ('S' >< product_info['version'] && 'Y' >!< product_info['version'])
  vuln_ranges = [
    # 15.4S train has 15.4(1)S0a, 15.4(1)S1 as First Fixed Release, using just 15.4(1)S0a
    {'min_ver' : '15.4',  'fix_ver' : '15.4(1)S0a'},
    {'min_ver' : '15.4(2)',  'fix_ver' : '15.4(2)S1'},
    {'min_ver' : '15.4(3)',  'fix_ver' : '15.4(3)S7'},
    {'min_ver' : '15.5',  'fix_ver' : '15.5(3)S5'},
  ];
else if ('M' >< product_info['version'])
  vuln_ranges = [
    {'min_ver' : '15.5',  'fix_ver' : '15.5(3)M5'}
  ];
else
  audit(AUDIT_HOST_NOT, 'affected');

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCva91655',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
