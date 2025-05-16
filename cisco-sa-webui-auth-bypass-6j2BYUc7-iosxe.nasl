#TRUSTED 3d6394a062f2399e19c0eca5e33e6315ee497946bffc6b75bf73c8fde9f1f664ec4964ac4d29d516010f66727ab853b6fc5ad13ed46400fbda3cbc12ec209934b8ffde4a11c6d1156e0d1e7bd11429fc8c534b1717f10ac5107bf802b350bbedd37684fad6ecdf29ba7ab5eb3ad5d14c810070db210f5a703bd16debe84fc4ac4e4cbd2994440559192f0c379f5c56a996b694d5233f03cfd884055ed574e81e936b5260eb349491ef33ad0000cbba5bd22d84ddf9494cbea0a61c5e9b26ae64da998654580bf785ddac1e7375d80a191dd851609d7d1ece6341a74d7622206edd52162171d9c27ab6373b9c90a0ad6f18c3ec7344062dc8fdeaa10161002785ff8687120d01fd8397d46b80d0aa9a022d1b20fbbd1ac053d3bd80ddc457d9cc63679819b4017c3e49196658d8e4674044451a86145e6066991812eab4b7cacf6d875b35b6525c9a1a440baf59d1da7c02dfcaba3eec110cc7fbf973f7c65f9f715888a07c1ea9df92a375ad50d3a77a06a54459302b8e1b01be686b8c5f5e1367f7311840ebfa44fdb62e62011b2cebc17971f644470ee423f48b865c73f6d6b35a7b195d50a8923af2e498f34a7758bd1555ed265d2b55cb114485b86f6afd561291c02d0083ada4946023f7bab0202772d5ed60f5a0fa26265868e95626b34a22c258abf3912e5949e873a7cb662e95bd9d3dded90f3f48f92c3f3a3f7723
#TRUST-RSA-SHA256 b29eb0ae29b1ab83c1a9936b7e13d99ee43968570022f627c589c42a1372449a79f7a85c8f57b770a4cf0f40ef7744c0a07071c4c47fdbb1552e9ceb50a42d4a3ccfbbcb5f91297fce37e41992446b4425ee9968f59b7caf5448c7829115b5a6a22e6e847ad9e8ebe495e0f516d5fb00cef45ad51306dde1994339ecdc379812b217d1e0309274312fc75082bd1148499771465a71286553e5f566f2a98e97dc846c3da9a28c271e41918297a4df6989089743207887d194267d433245bbff34041767906e68efb1c3e0d97df274988a007d37c79bcc2bdeb6125714e254fb33e45ddb0b689405d0cd5fdb7fb91e96a412c92cf84e7d1f171a26ceb63df7bcf0338d800acebc7715fab60a72118fbd779f67513b6d4083dfa209e3958bcaf439cfb56cc6f257959631da879f42bcd3dbc58341d19e938d342aa632f82d42f959c49491a823340f138ecadc6d35877a6be4bd313e543287dabd30a9a53df533fd61ae3c90c07f6d056c391e19006dd165acd5c078aee8ff3077525dd53acce9acbc33319244950c0411c93df9e6cf19f3d2d17bfdcb10b3cc8f26f785701a048e5212af1f53e7b9924f231a5fbfda9ca989d1efa91aacb6ebaa641e8285cbcb1406674352a1e9f98a27c161a11aadd7c08be6727b4735e2308e590fff2e7954fe577f26ed7f6dc34f5ab00a88d511a56a39f63e612077597a15214a5afb08d9a6
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(141083);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2020-3400");
  script_xref(name:"CISCO-BUG-ID", value:"CSCva31948");
  script_xref(name:"CISCO-SA", value:"cisco-sa-webui-auth-bypass-6j2BYUc7");
  script_xref(name:"IAVA", value:"2020-A-0439-S");

  script_name(english:"Cisco IOS XE Software Web UI Authorization Bypass (cisco-sa-webui-auth-bypass-6j2BYUc7)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch (cisco-sa-webui-auth-bypass-6j2BYUc7)");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a Web UI authorization bypass
vulnerability due to insufficient authorization of web UI access requests. An authenticated, remote attacker could
exploit this vulnerability by sending a crafted HTTP request to the web UI. A successful exploit could allow the
attacker to utilize parts of the web UI for which they are not authorized. This could allow a Read-Only user to
perform actions of an Admin user. Please see the included Cisco BID and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-webui-auth-bypass-6j2BYUc7
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7bdeebf1");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74268");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCva31948");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCva31948");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3400");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(862);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/30");

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

include('ccf.inc');
include('cisco_workarounds.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

vuln_versions = make_list(
  '16.2.2',
  '16.3.1',
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
  '17.2.1t'
);

workarounds = make_list(CISCO_WORKAROUNDS['HTTP_Server_iosxe']);
workaround_params = {'no_active_sessions' : 1};

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCva31948'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:vuln_versions
);
