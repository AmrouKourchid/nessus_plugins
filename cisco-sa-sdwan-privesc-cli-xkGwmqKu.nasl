#TRUSTED 4f08fe45944ddeb968af16b3b8e6523c13fa3c02a436c8800a29f97cb5080fe6b00ece80cf69de7f1194a848cf3594bd24b76ae775e3eada5d28e4b2e59412a10bc4d6d3e584f48100c37ea23c42ff4999f0f11ccab6f1533605c48b31e179d119c37564edab1bc0351a0fe80a1d47a068a4908fd56ea93c85bf2a5280c225c6a877471b04c2f7d77823315a0908abe7d32fc7c4c67c4650ac2c34e142add597bb028c642096444bf9acebeba7f279da76beedb951332bb2df5f5f28bcdb10d7741823b00656ff0fc778d0d47823496ba08fa1fb5f737709e53800270a9c68002f3ee66325fd4845db1dfeec7a6e2db560b3e8fb0ab441af44a00dece12b83a0e8d83c397c2cd6ae92bc025b8a06068090917358d6424276f380a71998a3c8585d1ccfe9fc806181859104b4d83968bc08cfb065505d00cd6ed7b08cc8de773c70f4d152853e366189cae054cad357c1786a102add51b7616913ae1b3d1d35dc2ecba4f4242c0208be8d43e79eb4b91b0de8d4c35aefb903c7814fd2705b9102331779754f74d2483c8bc442f7258f7ffcbdb61a810cc8c125f32cf1142681bd5db62f78ca9b34bb705a1942f8e72d97e68bffc7b7016da67faf7a81364334216c038c1ae954d492859737eb88b5b3790e7971d7805d158e3699dfd1be48e9d315740a4ea634cecf5881f29a7288512fce4e358d4dd44fbc881e4ed481b22218
#TRUST-RSA-SHA256 9e82c4586083b50196be0d3bd95e26ba2a64a23cc0b00ea4cfef02d9d2150d5848e127a5167ed8eac9345b5c5f34485c39402ca9eba9810f710dd529ed4a98eb48ecf4358e24d399d6b31fa23ad809d4d1942764b7e7049bb27c542e8f11f32657cec2dcde3cd689c4ae93848d930927358a5691c720157541c6354ab1234e1497e2177ccd7b977f1ab302a0515e468f4183cccf659f4b9fea913164f5e6f7b99a750b235822ea6d74ae182f38a43eaa0e64fe338e5e2884b9962295d858609d6e2fa127a8cda2d63710c3dc3b2d67d00492cd29c69cb830782b770746a1882da78052ee28f0947d561bad37b8086592d46ebac9ee8e492f54c1f5afc030019eb138714f798af3ec316e94326ca1b8d5d4ce19b3eff761940e8ddc89d1d9c712df9cd29bdedabb928cd6b3bcbef73fd827d52e7ea502e648ddcced2f337d06fc541b7c87dc673f5c652d51967f3aafe5154c3cf4e307b99b608d33200103a922e35db7f308ee0a8e7437568b44d0d94f77c0df3055f6b40965f6b406f3bfb23fff670d168adf48ddff08a726654fb87b8f0b5b3c6c921c8b27845e78fac2d3a6daf6b852fb27cbd7096a21216580727456e664bd15a6982c93da701afd2d363eaa09a0f33391f9806a5e2334828ee870ff43be4fe0018dde1bd064e4f3cac93d9688f120acb3169656935a4ac00b23cc8d2a8b307512c62f3597ce8e9e1a87b9
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(165528);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/05");

  script_cve_id("CVE-2022-20930");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvz46392");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sdwan-privesc-cli-xkGwmqKu");
  script_xref(name:"IAVA", value:"2022-A-0391");

  script_name(english:"Cisco SD-WAN Software Arbitrary File Corruption (cisco-sa-sdwan-privesc-cli-xkGwmqKu)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN Viptela Software is affected by a vulnerability.

  - A vulnerability in the CLI of Cisco SD-WAN Software could allow an authenticated, local attacker to
    overwrite and possibly corrupt files on an affected system. This vulnerability is due to insufficient
    input validation. An attacker could exploit this vulnerability by injecting arbitrary commands that are
    executed as the root user account. A successful exploit could allow the attacker to overwrite arbitrary
    system files, which could result in a denial of service (DoS) condition. (CVE-2022-20930)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-cli-xkGwmqKu
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?88c0c1a4");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvz46392");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvz46392");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20930");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(88);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:sd-wan_vmanage");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_firmware");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:cisco:sd-wan_vbond_orchestrator");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:cisco:sd-wan_vedge");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:cisco:sd-wan_vsmart_controller");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_vedge_detect.nbin");
  script_require_keys("Cisco/Viptela/Version", "Cisco/Viptela/Model");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Viptela');

if (tolower(product_info['model']) !~ "vbond|vedge|vmanage|vsmart")
  audit(AUDIT_HOST_NOT, 'an affected model');

var vuln_ranges = [
  { 'min_ver' : '0.0',  'fix_ver' : '20.1.3' },
  { 'min_ver' : '20.3', 'fix_ver' : '20.3.5' },
  { 'min_ver' : '20.4', 'fix_ver' : '20.6.2' },
  { 'min_ver' : '20.8', 'fix_ver' : '20.8.1' },
  { 'min_ver' : '20.9', 'fix_ver' : '20.9.1' }
];

 
var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'bug_id'   , 'CSCvz46392',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  vuln_ranges:vuln_ranges,
  reporting:reporting
);
