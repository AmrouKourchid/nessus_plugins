#TRUSTED a14755307f270c0724115f9f9e156e64a7df84892254796e84e8bfba6c9534b1835122e240f82908280b780344523199dde72130e8236baa691ee9829a32f021c180cd6f692ad5d2cbb92605f235d47dca97594e216ebf94850b7bbeb62a0cb8aa8386659a3860d6e288f5f2a8525a19e400af061491a95467d5ad9954750b5fcb8fa63f371abffcce3544cf975261423d3fb7d89f365941d4124328895d1590728191349cdbc052c710b68cc17d4180e38a4dc68c39493a682ee155f11826b354956b98783ad934cc7ba70390e7dfa8afa036f9d7bc912f205dce74659b9f0aad123b39149be18a30eaa83a9eab7952a2a4ac70e4e0ebe97faffbd0388709c439aab24ab541f54fa09d15544842dc3fa4db12d3cf13428d273dffe0dae28f7dc372c739837051959b3db2bfcc1670c98f316623c0001ab2722890d923c4dbed07ce32fe6af331ae44632b14989be1260abcb6f91fa5b5a219a4d957d97184420b252e122ead0d4dd4c17e96b9b9d385578ae6d2815460563828753bc2b15177606437e58b252104c65e0e3a4e96a48f5ff35631f897780a4592a59b7deeb511c4071fb2ceb227b8171cc7f1f1af77e32b8c7c8d2928e2cb2fb39d0c2379ffdcff79b1bb33049fe0de80ac8642b709e4feb0b091f1af052438d07d0336cbdb1dfda5410fcaa2edc109f472e4aff8b8779abf6977f88e95288b5557a591e6f768
#TRUST-RSA-SHA256 19aa7f6a80bdeffd5b0c608c84f8d75c8160385457b3e166554d3521df762938ac7ba4643fc07e880773e4262a8fcdc2e4f3df38829c34943b0b0e1e8d626c509442fb318096c4bec996f05ef8de55671ddf0b483083a97d9cca9513c2269f507ae7e01d9a226ee3cc25ceb46bb375fc559009a8598604ad54d41004a74cad8f0c8ab5103a875b2eba74058600da9e53881563c7b21434eec7a7aa8c5195b1fd98b84ebb47d3abd9f9a3a4f86c2ba951eb290b7afa55c8fe0a3bcee26f151ea3cd74c6675c114c96097d3a953cf6a1cfd5fc16c71af2a55140fec1100be571fddafc4d9c409d91f9a616cd2173f3da325e949bea89f9404cbed08a6db53e8d4e6fc84393fbb025bc9dee269c034cd084bcaa7d20cc4e03f4f446097c918cc22fb0a69a7964a6c5e019e306b1b0d6fd4d213451724a4f20e9ffcba8ade67a5dfc614ac5cced29112e63431a738a70bc9880c5ad5cf28f6e6e718872093d7df2fc924396190a56dd47cc1a53408ef15459e415ee3efbc0df1ea63cf0abaa75825ddeb11c603d2b96d5dbb7c549b6ad2b3bfa4f7fc4ce654cb70b58678d7a9cf9c47b7047d2a4db28c9aabf783c4291a2a56ead8f3ccc8bb15eecdac92ee61ff2640a8adbf4b8f4435a120e64faa2c6dc81f00777d7f44fe199ea60daab6d1febb96906790476e28a299c0a7038bd2c80a64ce01f94a19a24e192eb279522330edc
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(133001);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2019-16009");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq66030");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20200108-ios-csrf");
  script_xref(name:"IAVA", value:"2020-A-0015-S");

  script_name(english:"Cisco IOS XE Software Web UI Cross-Site Request Forgery (cisco-sa-20200108-ios-csrf)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a cross-site request forgery (CSRF)
vulnerability in the web UI due to insufficient CSRF protections. An unauthenticated, remote attacker can exploit this,
by persuading a user of the interface to follow a malicious link, in order to perform arbitrary actions with the
privilege level of the targeted user. If the user has administrative privileges, the attacker could alter the
configuration, execute commands, or reload an affected device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20200108-ios-csrf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e39a8725");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq66030");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s) CSCvq66030 or apply the workaround mentioned in the
advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-16009");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/16");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list = make_list(
  '3.2.0SG',
  '3.2.1SG',
  '3.2.2SG',
  '3.2.3SG',
  '3.2.4SG',
  '3.2.5SG',
  '3.2.6SG',
  '3.2.7SG',
  '3.2.8SG',
  '3.2.9SG',
  '3.2.10SG',
  '3.2.11SG',
  '3.7.0S',
  '3.7.1S',
  '3.7.2S',
  '3.7.3S',
  '3.7.4S',
  '3.7.5S',
  '3.7.6S',
  '3.7.7S',
  '3.7.8S',
  '3.7.4aS',
  '3.7.2tS',
  '3.7.0bS',
  '3.7.1aS',
  '3.3.0SG',
  '3.3.2SG',
  '3.3.1SG',
  '3.8.0S',
  '3.8.1S',
  '3.8.2S',
  '3.9.1S',
  '3.9.0S',
  '3.9.2S',
  '3.9.1aS',
  '3.9.0aS',
  '3.2.0SE',
  '3.2.1SE',
  '3.2.2SE',
  '3.2.3SE',
  '3.3.0SE',
  '3.3.1SE',
  '3.3.2SE',
  '3.3.3SE',
  '3.3.4SE',
  '3.3.5SE',
  '3.3.0XO',
  '3.3.1XO',
  '3.3.2XO',
  '3.4.0SG',
  '3.4.2SG',
  '3.4.1SG',
  '3.4.3SG',
  '3.4.4SG',
  '3.4.5SG',
  '3.4.6SG',
  '3.4.7SG',
  '3.4.8SG',
  '3.5.0E',
  '3.5.1E',
  '3.5.2E',
  '3.5.3E',
  '3.10.0S',
  '3.10.1S',
  '3.10.2S',
  '3.10.3S',
  '3.10.4S',
  '3.10.5S',
  '3.10.6S',
  '3.10.2aS',
  '3.10.2tS',
  '3.10.7S',
  '3.10.8S',
  '3.10.8aS',
  '3.10.9S',
  '3.10.10S',
  '3.11.1S',
  '3.11.2S',
  '3.11.0S',
  '3.11.3S',
  '3.11.4S',
  '3.12.0S',
  '3.12.1S',
  '3.12.2S',
  '3.12.3S',
  '3.12.0aS',
  '3.12.4S',
  '3.13.0S',
  '3.13.1S',
  '3.13.2S',
  '3.13.3S',
  '3.13.4S',
  '3.13.5S',
  '3.13.2aS',
  '3.13.0aS',
  '3.13.5aS',
  '3.13.6S',
  '3.13.7S',
  '3.13.6aS',
  '3.13.6bS',
  '3.13.7aS',
  '3.13.8S',
  '3.13.9S',
  '3.13.10S',
  '3.6.0E',
  '3.6.1E',
  '3.6.0aE',
  '3.6.0bE',
  '3.6.2aE',
  '3.6.2E',
  '3.6.3E',
  '3.6.4E',
  '3.6.5E',
  '3.6.6E',
  '3.6.5aE',
  '3.6.5bE',
  '3.6.7E',
  '3.6.8E',
  '3.6.7aE',
  '3.6.7bE',
  '3.6.9E',
  '3.6.10E',
  '3.6.9aE',
  '3.14.0S',
  '3.14.1S',
  '3.14.2S',
  '3.14.3S',
  '3.14.4S',
  '3.15.0S',
  '3.15.1S',
  '3.15.2S',
  '3.15.1cS',
  '3.15.3S',
  '3.15.4S',
  '3.3.0SQ',
  '3.3.1SQ',
  '3.4.0SQ',
  '3.4.1SQ',
  '3.7.0E',
  '3.7.1E',
  '3.7.2E',
  '3.7.3E',
  '3.7.4E',
  '3.7.5E',
  '3.5.0SQ',
  '3.5.1SQ',
  '3.5.2SQ',
  '3.5.3SQ',
  '3.5.4SQ',
  '3.5.5SQ',
  '3.5.6SQ',
  '3.5.7SQ',
  '3.5.8SQ',
  '3.16.0S',
  '3.16.1S',
  '3.16.0aS',
  '3.16.1aS',
  '3.16.2S',
  '3.16.2aS',
  '3.16.0bS',
  '3.16.0cS',
  '3.16.3S',
  '3.16.2bS',
  '3.16.3aS',
  '3.16.4S',
  '3.16.4aS',
  '3.16.4bS',
  '3.16.4gS',
  '3.16.5S',
  '3.16.4cS',
  '3.16.4dS',
  '3.16.4eS',
  '3.16.6S',
  '3.16.5aS',
  '3.16.5bS',
  '3.16.7S',
  '3.16.6bS',
  '3.16.7aS',
  '3.16.7bS',
  '3.16.8S',
  '3.16.9S',
  '3.16.10S',
  '3.17.0S',
  '3.17.1S',
  '3.17.2S',
  '3.17.1aS',
  '3.17.3S',
  '3.17.4S',
  '3.2.0JA',
  '3.8.0E',
  '3.8.1E',
  '3.8.2E',
  '3.8.3E',
  '3.8.4E',
  '3.8.5E',
  '3.8.5aE',
  '3.8.6E',
  '3.8.7E',
  '3.8.8E',
  '3.8.9E',
  '3.8.10E',
  '3.18.0aS',
  '3.18.0S',
  '3.18.1S',
  '3.18.2S',
  '3.18.3S',
  '3.18.4S',
  '3.18.0SP',
  '3.18.1SP',
  '3.18.1aSP',
  '3.18.1gSP',
  '3.18.1bSP',
  '3.18.1cSP',
  '3.18.2SP',
  '3.18.1hSP',
  '3.18.2aSP',
  '3.18.1iSP',
  '3.18.3SP',
  '3.18.4SP',
  '3.18.3aSP',
  '3.18.3bSP',
  '3.18.5SP',
  '3.18.6SP',
  '3.18.7SP',
  '3.18.8SP',
  '3.9.0E',
  '3.9.1E',
  '3.9.2E',
  '3.9.2bE',
  '16.9.3s',
  '3.10.0E',
  '3.10.1E',
  '3.10.0cE',
  '3.10.2E',
  '3.10.1aE',
  '3.10.1sE',
  '3.10.3E',
  '3.10.4E',
  '3.11.0E'
);

workarounds = make_list(CISCO_WORKAROUNDS['HTTP_Server_iosxe']);
workaround_params = {'no_active_sessions' : 1};

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvq66030',
  'xsrf'     , TRUE
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
