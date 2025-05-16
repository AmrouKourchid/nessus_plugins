#TRUSTED 87daec86058d7545329e4512a263ce75e62ff18be5cb393f1ed46b6289710433e8940ebd71efafbcf019b214b855afe73234d5e1aef4a6ace125d51300db551a487f6678e10f99a11ecdef6d7ed2cf39769af4bfd49044cbdfae0bbd9d8698eacbd9ca5e0f68c28a85d7d6809e8d2ca5fc6ccac36dd696332cbb16c50b7a9f3e782afa49c74fa52920f38a13ae1df4983d70c1fa9b964cd16909cec7df357e0a15e42e739703e142e25dd6a9812c52dfc775237d033c90bd6bf806eeb42f57bc6a18ef30b60ce099aa9bc208cdcffe99ede25c4716c75d311ab4ec57705ef8ac9d83160687f0226ef9f3bd2fdc9ee48937eae25b142c7d9599951a0408bd6a7b35918d32663ba52a3e348103013f8794c606a1578bed15dcd8af075acd13e398d7ff68f5fec3b448f8d51946949e3492337b199631f16d3a097ff591804328de19a2307b47853cbee89ebc0f02cb7b15c64fdb898666d51ba0b3e52001edfaa24fd58553dafe9e6d360b39fa12713fdd8ee9c3d3c4192f976011809034903d6e31608301e17d9d55fb00f7975f16276dbee1135501845bb85494aa0152c75f88778ad296f74c9d0bc9370d1ee886684b2bac275b78703695a90a661f4c6e341c136ec908d7ea700219b0a69b5ab9fab3510f3db281316787e9de617eb2cdf221dacf49bd7e06d4d669f6389605e7765d13d5ff58050378a88a42e1dfaccd5bb8
#TRUST-RSA-SHA256 9be4146a354727cb9961e39b5555a57fc93b7155a848f40c6e2bed676557a4d75d946cd6ff8ca899dfcb70eb13d3d38eb78d78187117914e7b15e34b86f8cabec24f56942563db914d785edf6829c8651783591dbf4da5df28950f9b30ac0d1d93e04311b569223dfd9e340e4c2aa223901a572cf0d05a912e7fc646c7d968f13c0d49a17f7d03a0cf8c502dbc80c481487ee0d0089a87c1051400ebe4dd808610b9c094febcd3906c152c8ac49c7c8c04bac5f31bd485fa2cfbdd351938e73459fb644de4a7983485637c244c0a5339ce500ef96a992847b54c01e89afa82cbb54a30cd100c4a58a42c3f93136e897ac3c566a2ebd85c4742d7ee9b0977c81d8d667d3512028def2b3c211ccaf932c0c5f592e920ca0e50541a6d97116cbe976aca7c5fb0b8cce9d282fbd18902c19304752f7bf5665801aee3a35f2d6d4c0871509aeb70843e53e07ecde142c41b91188da1cda95b79ffe4f446239c1401b9af6aed16760f1d48b6578f83eee89c924cf0944030d9b7dba7ac2a86e220ca84ccbf25239b166095d39fbf2a97c2a55b51aad54badc6737dd5e653de4556c53322d202faca4e88431a0b29434482dd4336923b45829c0306532beebe22411c7f72c2e0a21d02cdcfaf1bd02df54750c967f4859739040e74c69c5ec6239e77ac6297accd33927b87c3a217ff5aeae64e5937e869087872bbe0be35ae5a676028
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(129499);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2019-1755");
  script_bugtraq_id(107380);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi36824");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190327-iosxe-cmdinj");

  script_name(english:"Cisco IOS XE Software Command Injection Vulnerability (cisco-sa-20190327-iosxe-cmdinj)");
  script_summary(english:"Checks the version of Cisco IOS XE Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a vulnerability in the Web Services
Management Agent (WSMA) function of Cisco IOS XE Software. The vulnerability allows an authenticated, remote attacker
to execute arbitrary Cisco IOS commands as a privilege level 15 user. The vulnerability occurs because the affected
software improperly sanitizes user-supplied input. An attacker could exploit this vulnerability by submitting crafted
HTTP requests to the targeted application. A successful exploit could allow the attacker to execute arbitrary commands
on the affected device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190327-iosxe-cmdinj
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d6535745");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-71135");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi36824");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvi36824");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1755");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/02");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
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
  '3.6.10E',
  '3.2.0JA',
  '16.8.1s',
  '16.8.1e',
  '16.8.1d',
  '16.8.1c',
  '16.8.1b',
  '16.8.1a',
  '16.8.1',
  '16.7.1b',
  '16.7.1a',
  '16.7.1',
  '16.6.3',
  '16.6.2',
  '16.6.1',
  '16.5.3',
  '16.5.2',
  '16.5.1b',
  '16.5.1a',
  '16.5.1',
  '16.4.3',
  '16.4.2',
  '16.4.1',
  '16.3.8',
  '16.3.7',
  '16.3.6',
  '16.3.5b',
  '16.3.5',
  '16.3.4',
  '16.3.3',
  '16.3.2',
  '16.3.1a',
  '16.3.1',
  '16.2.2',
  '16.2.1',
  '16.1.3',
  '16.1.2',
  '16.1.1'
);


workarounds = make_list(CISCO_WORKAROUNDS['HTTP_Server_iosxe']);
workaround_params = make_list();

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvi36824',
  'cmds'     , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
