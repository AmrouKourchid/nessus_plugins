#TRUSTED 4cfe8471e648906771b131d58ebf77dc0d1a20964e3b2cd7583e681c667fda2f7827b737115937e8789dbbd445e073d5e7d2bb940a2bc1ddb4adaff213dbbd6328f2473cab7ab551804be20c2daf22302738bb6a13ff6add1487dc41c1a5907ae848c3351cf01395a8b81a4158d247954ac827eec9422be13c4dd6bcccc7d5022d13252bbe76a0b4c8d0d4fa4038b14255960849f6cf2140543607971759d4505d8fd0536f2f4c1617f2b49f21736ca1909b5d670a279fe0a41bdbd8bc35ab33ab3b630cebd71caa433ea1d9d62a7f9d3d3f70af05d57b3d5c7be2ec99467b47a84d0652808f35a836418d7f7a78f4dd4b802a986e8889bba8307ca40bb7959cf82e5b3681cc372e1002b4aff2dbc5337d9e034681ed814842eb42df3fbe57326ed053f9838ef7f00390011c8867488c2adda4e43c3f8d81a01767f178ff515b62863072e85589f7429114600581f6125e6a1bf08bccc4f0e97b5d651efedc2e8f097f701540f2b45d366307ba805e9f485f937a819609d3b5c4e592e179fd30b70d32fec612e3197cd6c2a17bf9b18f6474632283aad5fa838365228963c75b55215ba0a2dbdc9c93ed1106454867f2a867f2cc4f72118316eeb69efac5feea0cb55067f819b08fc828e36bc77568bbc0bb0ee8219fb0e28ab9134824d0304b7387d96ffc8e94de50ba2a7ed2e76acb3a1dd0b15aea273cdd4f1b9f45ba0216
#TRUST-RSA-SHA256 606f967d6e03fabf81a91c05a4803a04acad4a5c51c7996e54349412ff929107ff6293a4cc0e7fb8416c12f9f8cc8f87122816ea4fa48369e5a08a85d3e888e7a6d3c1bc300471e2be0ec4adbee31d49e0c857c0c3720908ea34345c7ace9f2a0f112e898fb5eeab46255e5341a6a2a38caaa137c7eeb9b1b130c16c12bdfc6f438a0257a68bc00b91a1a611948549c55482893144ef80291963449b91a4baf45b5a554f40de3167830296a8e357b9bd6aa4d8cb0887702a01a0240e21ff372e28ce915f77a191e0b54ab32ddf6810250de07dd4ae2f175edcc325d4fac6ddb82700e8dca8cda7b9a84706fe4599d69b3013c1a558b41dbdfedae08e293de0bb2f565455fd56ebd4fc687e404f09e5f922b10505ac6ba9e44c31e5335b018ff92ae64d5057e799d8683c6f2da38807ee9c8bcdef8bd6ae9aff7a8d851e1753f0a4ab376e789d38962896e1a23556ce6e458d27f5e1f98799867b41a1dcadf3878fd6fbc13716de6d61e998e2c982f629cf582147b8fc972e8ffcb9d281b85ad0854976c20ae986dc2c5df3ea4ac9591945a592143be9f957e10d6b1a74f50333ffad65bc47c2bfea448fc717bfd9e1bff57d00e069cbfbcc6ebcc81615bfe5ca31860ee5a8209a582234cd98f1d6fa4797102ed0d7022b7cfdb305eacc3d2439dc8ca2556b408f1b2c2ecc93d97ad6aa99ec02e279f35027836f3c76cdae8bc7
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(124332);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/31");

  script_cve_id("CVE-2019-1796", "CVE-2019-1799", "CVE-2019-1800");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvh91032");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvh96364");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi89027");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190417-wlc-iapp");
  script_xref(name:"IAVA", value:"2019-A-0132");

  script_name(english:"Cisco Wireless LAN Controller Software IAPP Message Handling Denial of Service Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Wireless LAN Controller
(WLC) is affected by following multiple vulnerabilities

  - Multiple vulnerabilities in the handling of Inter-Access
    Point Protocol (IAPP) messages by Cisco Wireless LAN
    Controller (WLC) Software could allow an
    unauthenticated, adjacent attacker to cause a denial of
    service (DoS) condition.The vulnerabilities exist
    because the software improperly validates input on
    fields within IAPP messages. An attacker could exploit
    the vulnerabilities by sending malicious IAPP messages
    to an affected device. A successful exploit could allow
    the attacker to cause the Cisco WLC Software to reload,
    resulting in a DoS condition. (CVE-2019-1799,
    CVE-2019-1796, CVE-2019-1800)

Please see the included Cisco BIDs and Cisco Security Advisory for
more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190417-wlc-iapp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dc39ed65");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvh91032");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvh96364");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi89027");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs
CSCvh91032, CSCvh96364, CSCvi89027");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1800");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/26");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:wireless_lan_controller_software");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:wireless_lan_controller");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_wlc_version.nasl");
  script_require_keys("Host/Cisco/WLC/Version", "Host/Cisco/WLC/Port");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Wireless LAN Controller (WLC)');

var vuln_ranges = [
  { 'min_ver' : '0.0', 'fix_ver' : '8.2.170.0' },
  { 'min_ver' : '8.3', 'fix_ver' : '8.3.150.0' },
  { 'min_ver' : '8.4', 'fix_ver' : '8.5.140.0' },
  { 'min_ver' : '8.6', 'fix_ver' : '8.8.100.0' }
];

var reporting = make_array(
'port'     , product_info['port'],
'severity' , SECURITY_WARNING,
'version'  , product_info['version'],
'bug_id'   , '"CSCvh96364, CSCvh96364 and CSCvh96364'
);

cisco::check_and_report(product_info:product_info, reporting:reporting, vuln_ranges:vuln_ranges);
