#TRUSTED b20b6251c9fd279689b0c46759befff87b448dc46f7c334f4930faf28542056d152a256e19979c855636156765f7973e6efe9f17d87870976ed18fd1f9faac538113a9b6dfd97d82d71f514b532fdf8aacf96e60f6d4155bcd948eb4650ea7ba52e8ddd89a6425fc6ed32e91e8dbbc0502e48fbb7565be9efa8ec3496bca4e9851fc3c216267710c25239426bf2618aea2e402d5772261e03937e0d315985a8c36c67c5883bd790ad27bbe6b89b98f464e11e6d95f8ea4ae91391af82bf69c29d1ac88d2e252ad28dfd65e59e5fa9adf0ca2537ffc2f62af20cf01e59286089bc43b640babb72e4973deb70531dda030d2af96dfc3523fd50f7336f710fe9408cabcca31acae442da037501c59e2b4e9cd9b20ba5662317ee2a2db78779545165245e7f8504bd0be119895fddc5f7e5434db91caf8c3efb8c4aed964624f68224a96f0ea93583179e0b834092a01af2d968c1558f82d6cfebbbf494f99a5ac32f44f5fdf1cb3db53485a9fa0e38fa1565120f31cb115735ef847a859ae95e4dd4cbbae0d118557ede906d9a8ec8f354baa31fc004135c5c0950fd0535b2b7fd5cf0e0f052d8af1a9aec3662505dac4d19a6af1149c74d280435deac05576e5a04e38d3a896353b5d4794a5d4c6fc6039f9cd151b1d597359bb00fd2a5af5dbf99a97b71e9e5743e1cdf7b26f87e8323c0f3cc16532fead5d435b56d2a7b66f66
#TRUST-RSA-SHA256 ad8d508747bc539ed0414d00348ce1988fa75ee41665aae065ddbb54d61827a186e0257f03f39c9ed758893af4979f8765154c91fbe7e8a1cbb0d063405da3b2c21f9f02b2dfde1f8d9d5b449cbb07b46397a0e720e125fb66511f74001781588b88b7d9f6f65450f08dec6eb2e45a48ef80c36173e097a23c5975fa2fd47ddc948524916f9a95d0acd27ee0c0890d29d18c9d77fac40b49caf0a4e6c166d92cb2b00819c6dce1af0c6116b6853dbdad309d68ad111c3891aca991c9069d5c71057fc0dede0f3033d5db5baf694c3b2d0416262e82e60d214bbffa6cda350635666574732ef1440c9ba7d0b6ddb625fa0ef4e45c98492ce11e17a0cd1abb440f51c59dfee30373592fe3e44e438270ecf0971d1ef8047591b72e4b4ccab8ce443e353d77a2543da88f7dd93308e95bf82ed7d62aa4b59afad6ee8dc2aa23878f9ebbe1a1476062d2eaf020dfff1491214a9114846f6bfa7b3aae155611e4942e01fc7554b81439a56c7941cdf77693272ae1567d919d98922fadb7ef62cfe60e18b25c6558d194ca57c2f56a5078cb5f159af51cb9eb5a41f29f5ba869d5cdefa1f07a2a760bf5406c1809efb7ff7792cf6b3f7f323c6182f539f367a2f8f07319e263a4c4e84b36e0ec3698dbeaa20db822030049add63b0358fe24e9dbe6e08b6e9abb4327a88e40115033ddaf25e34affcdd8bc4a442e97f7a729f364ae28
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(141114);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2020-3141", "CVE-2020-3425");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs40347");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu90974");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ios-webui-priv-esc-K8zvEWM");
  script_xref(name:"IAVA", value:"2020-A-0439-S");

  script_name(english:"Cisco IOS XE Software Privilege Escalation Multiple Vulnerabilities (cisco-sa-ios-webui-priv-esc-K8zvEWM)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the web-based user interface (web UI) of Cisco IOS XE Software could allow an authenticated, remote
attacker to elevate their privileges on an affected device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ios-webui-priv-esc-K8zvEWM
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?14445280");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74268");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs40347");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu90974");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvs40347, CSCvu90974");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3425");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20, 532);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/02");

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

version_list=make_list(
  '16.1.1',
  '16.1.2',
  '16.1.3',
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
  '16.12.1y',
  '16.12.2',
  '16.12.2a',
  '16.12.2s',
  '16.12.2t',
  '16.2.1',
  '16.2.2',
  '16.3.1',
  '16.3.10',
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
  '16.6.6',
  '16.6.7',
  '16.6.7a',
  '16.6.8',
  '16.7.1',
  '16.7.1a',
  '16.7.1b',
  '16.7.2',
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
  '16.9.5',
  '16.9.5f',
  '17.1.1',
  '17.1.1a',
  '17.1.1s',
  '17.1.1t',
  '17.2.1',
  '17.2.1a',
  '17.2.1r',
  '17.2.1t',
  '17.2.1v'
);

workarounds = make_list(CISCO_WORKAROUNDS['HTTP_Server_iosxe']);
workaround_params = {"no_active_sessions" : 1};

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvs40347, CSCvu90974',
  'cmds' , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
