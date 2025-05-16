#TRUSTED 565fa2d0c91258656916219006b2d18f4ca1ab8ea53dc755678e04e35ddeec750ea0d64c085cffeb8278750596c9d96bcabcd8637790781b24dcd72745297b08cbdf288af814127093145f452edf769dd07e02137c8a1fed6c48e4e9f209c9117021088a1af6261191a92ab166fd4edcf22289a7163a6feaaff5667cdb9760c681bdcc7c2a2c1e939d114cba34fbd44bcf898d924525fadffcdb3d7d72bbcebe138ebf38f72cd03897ef99af179e783fed229fd1fc134f6777f941e8be929b0b9763ffa580dc28c01f0b76f4655769fb47f8a85638624aefedf2bdc4d22ec0e784155c359c78444e06de4f7285e8302ddb1d268a04d9cd12b85fc9c2ca3914b287ed262ab8221afda6daa586709487f6a7e2170d6b9f5c51066826b8c2ed6742a45b94b33c22f7b299732e1e934532e34ac46562d5bc6ba1aee2043ae0451a14a4331826fa6d4fcfcd52fc82f9e873cf1c146dbf6b67d525b23c4398e1b668433af467e576d45b209a340c931ed8176314d9ad25d7fe63bfa655047d9a413ea5e7f56566e958c1905b6287aaf5347e066179744d68499bd477ca36f7b2bed84af5fd7426964e9ba2f3a03d00beeca3efe892d909b558e5c0a4950c27c4d00ef22e90d04b1f9c174c9f8d1dde606962873d73a61543796c79e0cfeeea0f69fef266c1c6f71287d7ce59b44581fa054e0f2b2017ab4dc918c3af2e09d5fe5429d7
#TRUST-RSA-SHA256 61f9e61a33592e4563afb3e00b7fa67e83f0766339ab0520f5796a07c9c6c1ba9acd285940e196bd1334fb890fcd1a1a87cb1a0832f65638e3d9dadc384dbfa9bbb38e0c5fca689148a485fc019a539277657033024e84b3734fd5b578ab18b4e6a443cd0a6ed08554070ed2fcdde33948acb913416ea08794c5028c9269614b4b41d2389e85b3f30eb51a82183526a25ea03391404b87b52e22ed4e94c0d1606c55cfaee0a24fa9fd21b480e3adff3293efdc33e06e320f9bb868bf76589291f5dcc1f6d74e8ba9dddc9bbdd5bebcbf3b9fb17258a8f91878735afd9c1975a516afae5b95cd8af8262d3fa00dbe3af44b1a642dc3e5b95d6b4fb42945f7baa71df5628151d1459bdab661c93572ea0f6db2dacabe01ecbe0d1978f674fb77d44d0644aaa396d16535c062dd4232f8ef96d502a3b66b2f0780f205e67da29eeca4a5caa93f5c3b8d32fbd4d9cee11a6ba06e855c4873a4ade7d27375ffaf1f69924a6941361176ca2f523e12ecc0f6144159dda4032302e70aa53d34bdd58cb51993807671d811607327691b9b0fdf6df6f2086613961896028d78e246672e2b202452532b9bfd942512f1769e3cb2cd1451231e767f5a52b84e0e69577973f4a45cd359e2f9fa159176278772c92d6a16a2486d5066fc6827c433c926e43d6af521ceac87b0b67830ebb4a7abc871b312e1cc6fea45a0f09c3e6817c25cd9a9
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(125032);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2019-1862");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvn20358");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190513-webui");
  script_xref(name:"IAVA", value:"2019-A-0158-S");
  script_xref(name:"CEA-ID", value:"CEA-2019-0315");

  script_name(english:"Cisco IOS XE Software Web UI Command Injection Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a vulnerability in the web-based user
interface (Web UI) of Cisco IOS XE Software could allow an authenticated, remote attacker to execute commands on the
underlying Linux shell of an affected device with root privileges. The vulnerability occurs because the affected software
improperly sanitizes user-supplied input. An attacker who has valid administrator access to an affected device could
exploit this vulnerability by supplying a crafted input parameter on a form in the Web UI and then submitting that form.
A successful exploit could allow the attacker to run arbitrary commands on the device with root privileges, which may
lead to complete system compromise.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190513-webui
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?220946d4");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvn20358");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvn20358");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1862");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/14");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list=make_list(
  '3.2.0JA',
  '16.9.2s',
  '16.9.2a',
  '16.9.2',
  '16.9.1s',
  '16.9.1d',
  '16.9.1c',
  '16.9.1b',
  '16.9.1a',
  '16.9.1',
  '16.8.2',
  '16.7.3',
  '16.7.2',
  '16.6.4s',
  '16.6.4a',
  '16.6.4'
);

workarounds = make_list(CISCO_WORKAROUNDS['HTTP_Server_iosxe']);
workaround_params = make_list();

reporting = make_array(
'port'     , product_info['port'], 
'severity' , SECURITY_HOLE,
'version'  , product_info['version'],
'bug_id'   , 'CSCvn20358'
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
