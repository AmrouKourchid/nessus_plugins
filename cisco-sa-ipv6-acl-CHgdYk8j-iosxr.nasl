#TRUSTED 67150b5b09dd3c0357f6cf0f7e0996c98361caf8df4bd3c939b74b171d8729fba8f77e001a10647c84fcc8d12e064600863d56ff70eeda72ae3a3ce22b5758e141eadc3c198062c7f6c66cf80595008ffd96eb3207a44e6aea51c16dba566585bbe4580c464c39d11a96699b0b76f7ad89cd3c74cbb521804c484cd86046d1140ee63d3094cdc4eda32ad36a15ca32583dd556031b4a42aab3b7a723a190b099c5f5b66ee6474e491453c8c9c1e9967b28cfc444bb4886e0de4bf5c54e7addd4cce9c627f7305b8a7cd49b2b30ba585ad1a6e86b91f1eb332624366431ed54dd7a53e5e0d82eefe7770999c8b4daf5b96324289a7b2e4660f7830c71bdcfc5030cc251aeab3593904c29c8650d8e6b410b8ac6c02864492162bd75833aaf5dcb4a4ebe2f134bf1b34b1281f619b46ac3ca904f666facd359cac49c20c0c8e265486bff9216be2549eb44236c72b41e5f75a3662e369db2b3ff3b699bd1ce3d93efbf669b87eb8969cdb4e9200637fc59af9977416ef68d1de8dc678b2d83f8c30bae16d0d50db541bd39011a044d3b28f1ae801f047f36c46e6e66c67e8710d9f6b668a9599662f96f2c33869b19ab2dc126e616898a97b331bb8a754f4874cf768645c6012d4169557c77fe001b56b5d69001a053d939c6c7fb041a41555e2d8eaa5c388b6ad287544e71bda9b0f2952528db70362247103718ac8bcf96fb03
#TRUST-RSA-SHA256 80d7fac1576042e2c5b646de7e81d8f4d0baf0856ca7c8422dc9c7381d91513f8525754c65884e7f23baa7e0d1cdaa72c352c7f0b742d745c74be6ae65adbeb8ca0b47506f108a6e1af1d4c7ea107f0a30d02eee6369fcb36ccb79f4464744add1d5ebfd31d0ae04160e9b181bf951e45b8ebfd656367f52cad9a76672bf4f7032ee52859c92045f6b63faaf10e1ced08b054d8ef9cec787db0ee0f6f0444d6f6675f2742fdcf3fbdb31d2ba702dd05229b8d53bc251dc00191f3e6546891d0dfbeb48e01478ec147ec1a912fb73b7e008b1afcf425ffb940aa1b85ca3f70879a95f2d7294b4055cca662f3c32eb519c53e98b651e3e8abd3919aebe7f2ea93406b2a9eb153ab97ddc1444e5c8d21a6c46aface7c0001a88aa5885bcf4ad66c8b108b30d6a0a9d10d5eeebfee21ec3f630471d4940f5b05b4037e3fa23496bdee4d25dd12cc8379b799b6551f651d6ddaf6f8b716f05ba3aaf3c618f9529db93d035106e83c960d4d5a4578e7a8c2ceee87cd8ac878d55d1798b40652957738e11db6cd2aa0299173abfd039fbe9e98673cfc2764d76cf872f5ba19ca505fa8ded6d7a182d25a7d79f755da007234d7af5ccd2923c7f4096736bd15d83f561bd5487be330ec703ee390885d8b89a8189c61a8d392bfad50e6faeaf76d7244b7529148c2c9338de1ee7981d403f76e23b3f14fc37e5fe92cea87fb4fc31e9f384
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(146480);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/06");

  script_cve_id("CVE-2021-1389");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvm55638");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ipv6-acl-CHgdYk8j");
  script_xref(name:"IAVA", value:"2021-A-0073-S");

  script_name(english:"Cisco IOS XR Software IPv6 Access Control List Bypass (cisco-sa-ipv6-acl-CHgdYk8j)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the IPv6 traffic processing of Cisco IOS XR Software for certain Cisco devices could allow an
unauthenticated, remote attacker to bypass an IPv6 access control list (ACL) that is configured for an interface
of an affected device. The vulnerability is due to improper processing of IPv6 traffic that is sent through an affected
device. An attacker could exploit this vulnerability by sending crafted IPv6 packets that traverse the affected device.
A successful exploit could allow the attacker to access resources that would typically be protected by the interface ACL.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ipv6-acl-CHgdYk8j
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?76e17295");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvm55638");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvm55638");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1389");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(284);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/12");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XR');

display(tolower(product_info.model),'\n');

if (tolower(product_info.model) !~ "ncs\s?(540|560|55[0-9]{2})") 
  audit(AUDIT_HOST_NOT, 'an affected model');

vuln_ranges = [
  { 'min_ver' : '0.0', 'fix_ver' : '6.6.3' },
  { 'min_ver' : '6.7.0', 'fix_ver' : '6.7.1' },
  { 'min_ver' : '7.1.0', 'fix_ver' : '7.1.1' },
  { 'min_ver' : '7.2.0', 'fix_ver' : '7.2.1' }
];

workarounds = make_list(CISCO_WORKAROUNDS['show_running-config']);
workaround_params = {'pat' : "^\s*ipv6 access-list"};

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , "CSCvm55638"
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  workarounds:workarounds,
  workaround_params:workaround_params
);
