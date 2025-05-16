#TRUSTED 4746562dd267f205d3662eb7a70ea988f54f9475be66c8b4762733d5352585afbe07afb8642c0ad1b48b7b6c2a44becb9e23e81e6a9f296b447eb0875693b0e848e04be28b858331eeab3e75b5dfbce9ed5cf21d290d8a67e7363115aa97373838292754c44e702b5aad816ca27a95a1b23b0d4a38e3536f349e2202f3b19846ae4e4a3f1cb34e34c1a93b7b7c373dc584cae78d00795515f89db7d6fc00a0459573cbf69cd459d98bb4ee61f9c955bcee81c0fbbbe2191433da1c421bdc00c255a38e45969fcb65530da73c4ce48f6ec94cf791bea53a0db6c7b3f371abda8ffe32384f17378d4f5735943840ab23c7598d29c45f1296302af31b78f04262589963b73519000c1931aa6f6601b4a087c048deb8ae762691e0c76f70294f604a83d0b29d47c7051e85392f3e9f353eee978aca48a0834db498e4e906720b2c9e9ca813efcaeca238e02affb5decf237a657a47b76e4500d2272a5262a0b59565731c1e5c03945fecc7a5da4975d03d74528d6dfa228bcb8b70e1b66880906b662c6e5ab8ef1f852cf055f877d71265ea46395e76e0f8ad49a4d1020ebb399a2e184fc049d1d730389a809aadd2f1cc873d1abc26ef31ef0d780abfded05722ec4eb6cfded5b3aad3233a44d075de42a9ae7bf510d6b1228548bc3275f2c2539c4aa2d6ce8d946e4aa0a16e2872c7f232cc996a4cb207aae51265938989ee7677
#TRUST-RSA-SHA256 8c85ff973d57ae8cf6354fd54f9784812be8cd764a46423a0c57c1bd5216f8fc74920602a72f02fba533eabe2a7b25e8df102835e295e2ee60691a49b7376f7ff0ffcf124c6906eda905b0fc1133ce40def53b96f6b6e4e3053cdb163d7dac7b7cb1c38498fe40dd92b02db71572c9acde9068b8258baa817a5ec0c45bcbe4e38725f6f5f6038c70bcad0297be9d9b99163d90e2074f7bccce83e8729759830e2ad3f1440d9840850353eb9331712fb5f4c1fd228287c0cd6841ac8ef87d71d567461a8dac687f85d6b5a15afb75f6ff8327989c7d6615c699e6227804524bb995bcb5571af06e91bec471d86ab32b6eb68e68436a80c2b74da8519f6709fd28b338523ec38a01a62a2a68e3f411ec2200fb1e3ae98aae8f3731e64ef0522fd7b38a68a2505cd63666ed1759de65a30b337f63b61d7484eccac5e1af9bffdc4dcb6be17e538d15671076da1a3e4777849e4c385320a67c9536d64db9988c13182f6c0c95db3c622cfedd880cce3edbcae27a206c20b18d707595126e3ed88423fa10d4298a19247df259242a3e3a463f648657e3266c4cee4bb6b52c90fa78faa4d20d116983eb53fc0eeef65d6671b1fda2f50f0fbfbc50c624009e24a499526975a1bd63eb7bd50cbe59fdc090c45904d558dde2a888c08dfba03813446cac0905227f268e42bf58de7971adbb45098764470389b9996da28cf34c8cf223b2
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(139325);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2020-3219");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq32594");
  script_xref(name:"CISCO-SA", value:"cisco-sa-web-cmdinj2-fOnjk2LD");

  script_name(english:"Cisco IOS XE Software Web UI Command Injection (cisco-sa-web-cmdinj2-fOnjk2LD)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the IOS XE is affected by command injection vulnerability. A vulnerability
in the web UI of Cisco IOS XE Software could allow an authenticated, remote attacker to inject and execute arbitrary
commands with administrative privileges on the underlying operating system of an affected device.

Please see the included Cisco BIDs and the Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-web-cmdinj2-fOnjk2LD
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a672eca9");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq32594");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvq32594.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3219");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/05");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('audit.inc');
include('ccf.inc');
include('cisco_workarounds.inc');

product_info = cisco::get_product_info(name:"Cisco IOS XE Software");

version_list = make_list(
  '16.1.1',
  '16.1.2',
  '16.1.3',
  '16.2.1',
  '16.2.2',
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
  '16.6.5',
  '16.6.6',
  '16.6.7',
  '16.6.7a',
  '16.7.1',
  '16.7.1a',
  '16.7.1b',
  '16.7.2',
  '16.6.5',
  '16.7.3',
  '16.7.4',
  '16.8.1',
  '16.8.1a',
  '16.8.1b',
  '16.8.1c',
  '16.8.1d',
  '16.8.1e',
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
  '16.10.1',
  '16.10.1a',
  '16.10.1b',
  '16.10.1c',
  '16.10.1d',
  '16.10.1e',
  '16.10.1f',
  '16.10.1g',
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
  '16.12.1w',
  '16.12.1x',
  '16.12.1y'
);

workarounds = make_list(CISCO_WORKAROUNDS['HTTP_Server_iosxe']);
workaround_params = make_list();

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvq32594',
  'cmds'     , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);