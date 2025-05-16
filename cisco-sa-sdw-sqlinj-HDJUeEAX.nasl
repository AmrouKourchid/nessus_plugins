#TRUSTED 406ac230e02c3cf3b937575f9254dcf9eedf3a0caaaf236fa49937347f7f5ef8f2d81e021e59439a9b5b08f4e47d1cb2a3f0db8663a51c94e18357e8a6e6846e4ec9748c2efa239a54f388879942db8fbdab3fd1842bc8be6b43ab7ea82f5b8427ada9f606323d9c513a88ed46db99ced8f45711c90c5cd551516acdc572b1f0995ab9ed576c39cf59ee38a2f4f90a08bbb6aa5f28c2d10cf7f140973ed31325242046f1d6ce8f56040a338b17bee1e3a1f754cd880a1677e393a820be2cef403ff5092165387f3208cc5f3af70e04a23a4d0693f237e5334b68ddc6f2f81ad3f08f29505f0c20cc85c1a3f17f02d733f8954b6adc262607e9c6e8addabe7d0361ac2f1edca93bcca0316326c15851fe4309652e12e99e930cb4b8aedb0095a5e002890204b7e06bc46ec01fcd95cf0073012dfab12729bdfca0454d201ff229113f6964e2d2b1eb6defa877bd06e9dc2ca108a228d6e83d81bf1aae2f979a72ca33b8388b6e00c41be08d1c23af28fdce45289ab4633818d652c4c4c436e3dfda7e4eacc7053fbe676880d46a322faee67dc2c9440ed0dc8c3ff77d9693d246c60b6093e04ace4d140242d684048b19aa6fc7b1ccdfd3748b8484ec2db0e8b6cd6e1e1cb76b70ef8264372ae4fc1e12a1e077a4375892833b838af57ac0e5b2138b8ba649e2ffd4e5ff53fce3e5f87a4602ff36c9d9a464b43666f78097928b
#TRUST-RSA-SHA256 800e7f540aeafc53223baef3f8945b8b3e8f60cf297c1105313855ec00b470c885b208e00436f02ce9db0edec9b9269b1d8ca9b859344e1071c9404b0f6e5598c925df063b8b4d8c36f5ee4b554bdd2deb8a7719e29bdf1d9c5967f56b7c7cbf71ee69130fbbe5b859c9d5026796eafef9a6380f1ee5c275ab8e1f81c22398f2ee633f68f092435aee3a2f427c2bf0fea73786d35a150e064fbc010710b876719d0abd69720535c4fe2855a2bb9a10b9d783f67e6e6c753caab14bad0c5ce2b54ddc5f5a6412b4e5bd020597d9b05b12031bb42d364531c56a066bdf3f234f6dd69e6d7169219b3e61578b1c0097e9f75a92646c29b791ac9b4f22d5669b62c11ad2e1fca372c98cea949898f818ba5816759bb9211b90d21143582875dff11f22305912cc95e53e66ece55a2cd86fba8a10a2c9d0ac9b731f0701903978dda029732e173b873eda018d3090568821fe534e7d0aac944d7b8f4e59518f583292809d79ebeaa157cfa4d34b650e1a2280661a4a8ce8e8b67c88b0018e15204402dadbfdc972c4b1566bd1c7e6a8e953aed1bd901a7e07e7d05c51687d2cc39f2ae49c36908db5a4d70e82b48d0c222e6efa37aef9cd3a9a7acfd3c0c0f70b59df93d9562809e758ac1e53810ca8263289d48132745750518751e8593764fb45d4e3b79b29edc54b67c1efd36d90ba184248320cad9e0ad6546723ca730de18004
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(150052);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/18");

  script_cve_id("CVE-2021-1470");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu92477");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sdw-sqlinj-HDJUeEAX");
  script_xref(name:"IAVA", value:"2021-A-0118");

  script_name(english:"Cisco SD-WAN vManage SQLi (cisco-sa-sdw-sqlinj-HDJUeEAX)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN vManage Software is affected by a vulnerability in the web-based
management interface  due to improper validation of SQL queries. An authenticated, remote attacker can exploit this to
execute SQL.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdw-sqlinj-HDJUeEAX
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9e0885d9");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu92477");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvu92477");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:M/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1470");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:sd-wan_vmanage");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_firmware");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_vedge_detect.nbin");
  script_require_keys("Cisco/Viptela/Version");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Viptela');

if (tolower(product_info['model']) !~ "vmanage")
  audit(AUDIT_HOST_NOT, 'an affected model');

var vuln_ranges = [
  { 'min_ver' : '0.0', 'fix_ver' : '19.2.4' },
  { 'min_ver' : '20.3', 'fix_ver' : '20.3.2' },
  { 'min_ver' : '20.4', 'fix_ver' : '20.4.1' }
];

var version_list=make_list(
  '19.2.097',
  '19.2.099',
  '19.2.31.0'
);
 
var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'bug_id'   , 'CSCvu92477',
  'version'  , product_info['version'],
  'sqli'      , TRUE,
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  vuln_ranges:vuln_ranges,
  vuln_versions:version_list,
  reporting:reporting
);
