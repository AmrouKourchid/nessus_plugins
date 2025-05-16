#TRUSTED 385ce18da94875f1bae652a5f6c3f2f86533e3afbe864b26e900f02709a6f3955ec6f19e002c092c1816301039887a8cbc2b37985ec86faec0e13d27bdfb4acdb093026a02b37777c7c7618af4bf35e118179f627d7a8d011d4e689da87b0a3144b1e3ca3dc24dc445da499d12f8a2f7b57439260821e71b8e0c6cfdbfff3f96d4e6cc4ec917c0ba488afc379d7ffb4bea48f83ffcf74405d97f8dd786f63a3c0fe05db43fd24ea9a6d7b7a1d923483049b424b72efc310fb919576cd8866a3fd6119b9600e58f4c74ce534acd40b407fa21ee43ebb399a8577a55d199cd58c0563fad500d25508645ffa138d60930c3bd4baaaf0a75ef34177fa19f2e3808dc19e35cf711bbb447c792194692e56819d6ca281101621a25ce9a1896f144197f6ecebed32846e37460f0f7ff12e304e0a95ee1d0f15d33cc3d84055492760b9d8b4f1c3318de4ed2b0e311b31e00b588705c11d1277e3bbc4725fb51c50a94d5726003787dc77b2fc516e9315d30dbc62497f4e6fdb5d224781781460ea4f959af1970a01817fbe455ec139a52d8b03b23a9444b5942aa679f45e1bf340667b1dc7dd2f69d2308bb12e0a1f7676af7da2c7b0e4cb1e6c60931d5209ef5c4fb3f2c980eb66deb708693a026e4d3b93b5de5654f7bc40865ac85323eef1f312a88193b600eefcd75ef66050bb66d39510151624d78853da2dd2836f1208b7ab670
#TRUST-RSA-SHA256 8e0505012a226dc54512c26bbce30f0680a505c2d8d51ef11cb564942c339d3a632f84a462ce312dc5f440eb0945e63974ed2e10e969355fa18c396f499713586756f61346d8b61b2cc312f5f639a9854de646deeb33dd739c5ca1bf1bc04c7ad28b6c12c55fa31fe1d8334aeb775bb711fb328278909d604aee53209c3ffb2f3196db05b3f7f52b8f87f47f75dd26c3c2d30f07c4ab1a41aa8ed8a96ac0f779a1588b797ceffab4a32197e8a989f4cfb05cf267a1085f4e72a90ca91c2a9c234d48217db3a2ece34e44df1524beaad9ad36b5f4942dbd59e0e16a966a68dcd7af2cf8d8777cb615342f2640d903ba993b217be13042c20d1866fbd3cad6a953ed8b733027ee28f0c0bee19e2b904dc8a3344e2c1c68f34c41319f31f6ebf7ef5e1865c6a945b012a2825c8a8758b8d48958adeac3a12fb074840adfd697b9e589cbd7e3ee2a10cc11e0d75a40bf9a8259fb99cf8168cb85c5caae0dffd3b7ba7a0dd561b28f5d23c9c127a3f7294c95ce261649b982ecb64018f74e0051c2a3e424d3d2be961e57bcb566fc8ead9992d0810fc418573eb9f1bd6a77b70c241e300588ebf14e9f20d89e2f581a1b53398a9a523b105b419f68499a4f2da305d2b2f4f6c89f6846f3024dd4b5af46d9d4755df687015900a97f67518136bdcafe10497ec8b69805117e11d8cf56acb708e424b7f474b769f61047711fa1501de9
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(144503);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/09/28");

  script_cve_id("CVE-2020-3428");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr96076");
  script_xref(name:"CISCO-SA", value:"cisco-sa-dclass-dos-VKh9D8k3");
  script_xref(name:"IAVA", value:"2020-A-0439-S");

  script_name(english:"Cisco IOS XE Software Wireless Controller for the Catalyst 9000 Family WLAN Local Profiling DoS (cisco-sa-dclass-dos-VKh9D8k3)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE is affected by a Denial of Service vulnerability in the WLAN
Local Profiling feature of Cisco IOS XE Wireless Controller Software for the Cisco Catalyst 9000 Family. This
vulnerability is due to incorrect parsing of HTTP packets while performing HTTP-based endpoint device
classifications. An unauthenticated, adjacent attacker could exploit this vulnerability by sending a crafted HTTP
packet to an affected device. A successful exploit could cause an affected device to reboot, resulting in a DoS
condition.

Please see the included Cisco BID and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-dclass-dos-VKh9D8k3
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?53ee1c87");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74268");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr96076");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvr96076");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3428");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/21");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/IOS-XE/Model", "Host/Cisco/device_model");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

model = product_info['model'];
device_model = get_kb_item_or_exit('Host/Cisco/device_model');

# Affects Cisco Catalyst 9300, 9400, 9500, 9800
if ('cat' >!< tolower(device_model) || (model !~ '9[3458][0-9][0-9]([^0-9]|$)'))
  audit(AUDIT_HOST_NOT, 'affected');

vuln_versions = make_list(
  '16.10.1',
  '16.10.1e',
  '16.10.1s',
  '16.11.1',
  '16.11.1a',
  '16.11.1b',
  '16.11.1c',
  '16.11.2',
  '16.12.1',
  '16.12.1s',
  '16.12.1t'
);

workarounds = make_list(CISCO_WORKAROUNDS['show_running-config']);
workaround_params = {'pat':make_list('device classifier', 'http-tlv-caching'), 'require_all_patterns':TRUE};

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvr96076'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:vuln_versions
);
