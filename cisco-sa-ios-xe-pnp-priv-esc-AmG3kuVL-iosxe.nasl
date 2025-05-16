#TRUSTED a3211aad72e22c563d3824d320dd8d6828216500d76c9836b92d5a93ceff805df78baca335bfdfacc10373b54e0858b787b87d415615bd93889676a93b593d98f9ce917f7d1d4cd48ae30fa949be1ab75cb2603706059b9c2445104c9555938b489b8322875687eb1912a7e43385e329fb89dc66f7e129a6e04aa182a14569569165f2da091adafe01e5cefcb17eb9fc0c38ce80cdf12d59e0c030406c657e4bfd06738bc91c704cd5dceaf3c7ead0f4f025b6d6fb250d26c544cfc149d43b833a25e1bbd18a7f33e47814e582f3c9eeb4a130c25bed354ad812e5925cf4ce85535fb498f4ac9f3785751796cc4cbb81f442d648c34861b529576f4ffca6cca8f3e5ba86141713e93825bf2757e9d9d2966872c2aaeb3dbf963b684156b216cec4a2746d09240965011feba9427d3e81fbe07fc60c049a861d22ccb5d7b966e9c7ce4db476b2e853865227a17216432e9508d016fddfab1228ef5e979f51e7f4f4295a494458c1a4343e914d85ca3d0fdb49a892fccc9443ed0c8ac135eac6e01c2aa4bf5f7641cc25d9d58cfbea295a9d222eab85b80907099f4ed9d74bafc4cc7a1e1367bcd6e81c00f5ff7acc183d175557a3e47e6766d6c85a74f37864dfe768bdbcc1a74c0c463df9639e01ab1c48f9d549fd9ba754209db5e906f728f42e0433e0bd9c6c01031fdb6b63de1fc5fae0804fbc60eca5326059eaa48c158e
#TRUST-RSA-SHA256 3538477ff5d60b8553f2a49f253e23a14ee8964837d9064835ed9cf42f6785cbc0fb57db86c2ec4606c06ae106a379fe16ca6cb3789f5697a1761e2ee5e420647f423aad6e39ed1d923b2ac131a29b7e750b24b1a6b9ae0d3647879db8ac4a236043309284b58c0b7a31b1671e14c26ca402f6f9c34d52d5bda9715df1971d12032dffc58c38ea8b8969559a62cdf8e0d165915c35e87477f85c17ddc78110ff9cb7077211ae5a1f724009a79fd0a48a12eca3a12d5a6e319c4c4fc43871e80b4ea8a2263e95a32ab1307262b999b5069ffffee595896659ee67ef36d25b3c76d99435536062136f704d994e1d0343c4bcb87c82d152d025a6c79c2d198f9742eb21378d0dc0c6e2fba461f75d977723c7d7c007a7dec1ee91cf551f53e0c6fef8bb8aa7edfb79c054310a4673bcb95ea9dc51bab6ea56c1b521a2e98bf192f572769c3d5b2db67244c62a147d8bfbfaa59f305fc10c5b25e360a20f57add0f19fccc068c0ce98eeb19d450524c3f0c31e086d6c69e956ffe1673b69e12247edd118274dbed93711da6fc831f2ea301b7d395f37735ab47e2177ea315cbadc023e5d8a2e4f234bd530b0c931462176e90029249c45097294f4e6c3de49e5434050e3d5af7a19d50f9736491e50f8656391742984af008e3523f5adcc916ebb53e8993d62bd431431ae05effeaf0f70b86fdc0bf229d5afa130d043864402e2b9
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148107);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2021-1442");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt41030");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ios-xe-pnp-priv-esc-AmG3kuVL");
  script_xref(name:"IAVA", value:"2021-A-0141-S");

  script_name(english:"Cisco IOS XE Software Plug Play Privilege Escalation (cisco-sa-ios-xe-pnp-priv-esc-AmG3kuVL)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS-XE Software is affected by a vulnerability. Please see the included
Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ios-xe-pnp-priv-esc-AmG3kuVL
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9e65821f");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74408");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt41030");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvt41030");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1442");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(532);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/25");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list=make_list(
  '3.6.3E',
  '3.6.4E',
  '3.6.5E',
  '3.6.5aE',
  '3.6.5bE',
  '3.6.6E',
  '3.6.7E',
  '3.6.7aE',
  '3.6.7bE',
  '3.6.8E',
  '3.6.9E',
  '3.6.9aE',
  '3.6.10E',
  '3.7.3E',
  '3.7.4E',
  '3.7.5E',
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
  '3.9.0E',
  '3.9.1E',
  '3.9.2E',
  '3.9.2bE',
  '3.10.0E',
  '3.10.0cE',
  '3.10.1E',
  '3.10.1aE',
  '3.10.1sE',
  '3.10.2E',
  '3.10.3E',
  '3.11.0E',
  '3.11.1E',
  '3.11.1aE',
  '3.11.2E',
  '3.11.2aE',
  '3.13.8S',
  '3.13.9S',
  '3.13.10S',
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
  '3.16.8S',
  '3.16.9S',
  '3.16.10S',
  '3.16.10aS',
  '3.17.0S',
  '3.17.1S',
  '3.17.1aS',
  '3.17.2S',
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
  '3.18.5SP',
  '3.18.6SP',
  '3.18.7SP',
  '3.18.8SP',
  '3.18.8aSP',
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
  '16.9.6',
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
  '16.12.1z',
  '16.12.2',
  '16.12.2a',
  '16.12.2s',
  '16.12.2t',
  '16.12.3',
  '16.12.3a',
  '16.12.3s',
  '16.12.4',
  '16.12.4a',
  '17.1.1',
  '17.1.1a',
  '17.1.1s',
  '17.1.1t',
  '17.1.2',
  '17.2.1',
  '17.2.1a',
  '17.2.1r',
  '17.2.1v'
);

workarounds = make_list(
  CISCO_WORKAROUNDS['HTTP_Server_iosxe']
);

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'bug_id'   , 'CSCvt41030',
  'cmds'     , make_list('show running-config'),
  'version'  , product_info['version']
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  reporting:reporting,
  vuln_versions:version_list
);
