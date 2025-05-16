#TRUSTED 931d5f90a17b770b750e8bbaba681c5f15a0deca1832bbe4166391f0c49802455ca43d39c2d7ca6b0da6be71081bbb533591c2dc25514a890dd69495818f6aee42266b28e3d8ba992116eae2ae9e667cc289d0a7b22964abc7d65f46bc070c89f271d00809631dc7745fa6bb5978bbcc6ceef975b7b9dacaf5a710abdfd77b3dc107f3ea13e017503dc5c3b3ccb18303b0d823baedead666aa1e0d7a528a78e374a60bb1612503eb405f6dd920bf098e830b56caadc4cdeab0d959fce650ff3fa65aca821571578616ba2164b3e691b66a395c52fcb161c752f0ea652ea2c503ec3b5a33e1ff8ee9214ab195b2dd13f050c03240f763cc1ebad43ca98feebd0671639c67aeae4c01e2548e4806dc5904f69f045370844c0cc52e3e1b1de7bc55141c3d561e95bc77118e981d86235422853dac2605f65580d9c9d772aa4f72dee56b0639db121f895424619c7a3fbc9096611d73935b5eae507b64c90f00e84adcf7c4561915deaabcd8fa43492a6737678b6fdd93f715dfd45dd78e416b5c46c841490c7e70028b811c7599913601bc25a76bee44f959a0835c5beb6cd4d2a069fcf89a3a88af627011fd972c6de3b441e11f1dd6d6eb3cd67fd328b8f28fae2afa0c3ddbae66d2ff71fcf41c796e60e8000f19e0bfc8fdbd0c2953f927c331afc3e17596e61926118887d22b827844c43f2fdc743e368fa069809de2f85a18
#TRUST-RSA-SHA256 0d48a60eabdc07246773ce3fc03411cf3add6dd3cf76c4f72720417c2957f1380e3e0d04c73201dfcfd339f0e1238dae923b6ac53bb300bfd5408999f2c5d36530d43923f7d16e5e10dacad80f03296628d81592c812d9451f3642114d218d779f4f30e54b0d2a6dea186df1e5edc13680dcc6bd55d76e3d0320e49f6a9d356f6b3a7f2a82b6d7497cc733252159abafced680a3b7d1c6cf51a4e154ab1e6111029d0b213b8d7d96eb5cf0b8739cf036d120193bd6b1c60ac94cfce83d9c60f04619326800a75a6463f879e2eac5b9587cdfe19df492de7013cf9930a1c0661c391eaf979a9db067a3c68cf1ec0ef7c859c6bb85a506e4417e7eba8d7e58df3e7eae416a9b8c123e8804f9216f6bd7dce85b38c25f0a9b292a608427f83e0408a4ecb5bd699e4766027e781d80367e169f84dc0b3a2681d77944bdcb74790587af4d8e3203ec338dbf474c498d3b581c1964b47bf8257a62dad1ffac8b7355b817146d6921618e3e215661c22a2ad75ab1ca0737571f7d040a181a103193d98b0d62dcbe2589efe5a5238244e19bad7e987da38f0378edaa58fac1d35a24832bc057a481a30afe761f40b400f38e4023def44ada746a78b1353e2d9de169fff14baa11d9a36cd4818924c18c8e929c09a2d0f5d4d004fae76ee5ebe497077ac4972273d583b16a8513b8a05c71b9c410dfa6ed5739bb73feed3a7e0c65f07245
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(123789);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2018-0282");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvg39082");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190109-tcp");
  script_xref(name:"IAVA", value:"2019-A-0097-S");

  script_name(english:"Cisco IOS XE Software TCP Denial of Service Vulnerability");
  script_summary(english:"Checks the version of Cisco IOS XE Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is
affected by following vulnerability

  - A vulnerability in the TCP socket code of Cisco IOS and IOS
    XE Software could allow an unauthenticated, remote attacker
    to cause an affected device to reload. The vulnerability is
    due to a state condition between the socket state and the
    transmission control block (TCB) state. While this
    vulnerability potentially affects all TCP applications, the
    only affected application observed so far is the HTTP server.
    An attacker could exploit this vulnerability by sending
    specific HTTP requests at a sustained rate to a reachable IP
    address of the affected software. A successful exploit could
    allow the attacker to cause the affected device to reload,
    resulting in a denial of service (DoS) condition on an
    affected device. (CVE-2018-0282)

Please see the included Cisco BIDs and Cisco Security Advisory for
more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190109-tcp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f9a0ef5b");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvg39082");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvg39082");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0282");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(371);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/05");

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
  '3.3.0XO',
  '3.3.1XO',
  '3.3.2XO',
  '3.5.0E',
  '3.5.1E',
  '3.5.2E',
  '3.5.3E',
  '3.6.0E',
  '3.6.0aE',
  '3.6.0bE',
  '3.6.1E',
  '3.6.2E',
  '3.6.2aE',
  '3.6.3E',
  '3.6.4E',
  '3.6.5E',
  '3.6.5aE',
  '3.6.5bE',
  '3.6.6E',
  '3.6.7E',
  '3.6.7aE',
  '3.6.7bE',
  '3.7.0E',
  '3.7.1E',
  '3.7.2E',
  '3.7.3E',
  '3.7.4E',
  '3.7.5E',
  '3.8.0E',
  '3.8.0S',
  '3.8.1E',
  '3.8.1S',
  '3.8.2E',
  '3.8.2S',
  '3.8.3E',
  '3.8.4E',
  '3.8.5E',
  '3.8.5aE',
  '3.8.6E',
  '3.9.0E',
  '3.9.0S',
  '3.9.0aS',
  '3.9.1E',
  '3.9.1S',
  '3.9.1aS',
  '3.9.2E',
  '3.9.2S',
  '3.9.2bE',
  '3.10.0E',
  '3.10.0S',
  '3.10.0cE',
  '3.10.1E',
  '3.10.1S',
  '3.10.1aE',
  '3.10.1sE',
  '3.10.2S',
  '3.10.2aS',
  '3.10.2tS',
  '3.10.3S',
  '3.10.4S',
  '3.10.5S',
  '3.10.6S',
  '3.10.7S',
  '3.10.8S',
  '3.10.8aS',
  '3.10.9S',
  '3.10.10S',
  '3.11.0S',
  '3.11.1S',
  '3.11.2S',
  '3.11.3S',
  '3.11.4S',
  '3.12.0S',
  '3.12.0aS',
  '3.12.1S',
  '3.12.2S',
  '3.12.3S',
  '3.12.4S',
  '3.13.0S',
  '3.13.0aS',
  '3.13.1S',
  '3.13.2S',
  '3.13.2aS',
  '3.13.3S',
  '3.13.4S',
  '3.13.5S',
  '3.13.5aS',
  '3.13.6S',
  '3.13.6aS',
  '3.13.6bS',
  '3.13.7S',
  '3.13.7aS',
  '3.13.8S',
  '3.13.9S',
  '3.14.0S',
  '3.14.1S',
  '3.14.2S',
  '3.14.3S',
  '3.14.4S',
  '3.15.0S',
  '3.15.1S',
  '3.15.1cS',
  '3.15.2S',
  '3.15.3S',
  '3.15.4S',
  '3.16.0S',
  '3.16.0aS',
  '3.16.0bS',
  '3.16.0cS',
  '3.16.1S',
  '3.16.1aS',
  '3.16.2S',
  '3.16.2aS',
  '3.16.2bS',
  '3.16.3S',
  '3.16.3aS',
  '3.16.4S',
  '3.16.4aS',
  '3.16.4bS',
  '3.16.4cS',
  '3.16.4dS',
  '3.16.4eS',
  '3.16.4gS',
  '3.16.5S',
  '3.16.5aS',
  '3.16.5bS',
  '3.16.6S',
  '3.16.6bS',
  '3.16.7S',
  '3.16.7aS',
  '3.16.7bS',
  '3.17.0S',
  '3.17.1S',
  '3.17.1aS',
  '3.17.2S ',
  '3.17.3S',
  '3.17.4S',
  '3.18.0S',
  '3.18.0SP',
  '3.18.0aS',
  '3.18.1S',
  '3.18.1SP',
  '3.18.1aSP',
  '3.18.1bSP',
  '3.18.1cSP',
  '3.18.1gSP',
  '3.18.1hSP',
  '3.18.1iSP',
  '3.18.2S',
  '3.18.2SP',
  '3.18.2aSP',
  '3.18.3S',
  '3.18.3SP',
  '3.18.3aSP',
  '3.18.3bSP',
  '3.18.4S',
  '3.18.4SP',
  '16.1.1',
  '16.1.2',
  '16.1.3',
  '16.2.1',
  '16.2.2',
  '16.3.1',
  '16.3.1a',
  '16.3.2',
  '16.3.3',
  '16.3.4',
  '16.3.5',
  '16.3.5b',
  '16.3.6',
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
  '16.7.1',
  '16.7.1a',
  '16.7.1b',
  '16.7.2',
  '16.7.3',
  '16.8.1',
  '16.8.1a',
  '16.8.1b',
  '16.8.1c',
  '16.8.1d',
  '16.8.1e',
  '16.8.1s',
  '16.8.2',
  '16.9.1b',
  '16.9.1c',
  '16.9.1s'
);

workarounds = make_list(CISCO_WORKAROUNDS['HTTP_Server_iosxe']);
workaround_params = make_list();

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvg39082',
  'cmds'     , make_list('show running-config')
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
