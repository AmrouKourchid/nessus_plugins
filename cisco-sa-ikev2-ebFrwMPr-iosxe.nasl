#TRUSTED 780e519c840b84a45a505fc5bc4cacc5ebc17dac56dcc209a7f6c3309be52fa7cb06740f93683666948e3ebde26f1825b28ca73c67cce26053152d1fc1d331628b0be5bb6cc7865e8ae6e6fb87f095a52eba6525e002e6831e528c0ee42ca29c326ebf237a77459e5891f3334e2dc32f857ec530e76989cef4e5d4e34e6816cea0af175f544b6fbaa1152d1748ebe84d8235e46307b7561711c73068a1192bde4ee5848cd0ec970368e46c5fe3492c2a24e5872e9fe5c3f926c4ae619fc2fb2efd82a4b7aa116ce2f28c6103ef9f15dcd3999dbd348c1d71557f1b60c5bb3b48e92c0404adca5e5e0919e286ecf12757911157a5c781cbd4c5966b546958f457c022e05cfec314a86b0c800f01b0134b39970f8d688f25066c63087cfc282140e87a73a50c77aa31f3030ecfb3367d2e10c73b1c3b6ddee1efdaa09dd27441d333c986dc12309c99b214789ffb06169cf43668bb43a8632c77c09475c4012c2b7aaec66ee07bbf0184479bd47c4048c5eb865bba029f8222d8805983f784f9b36a69d6174924efbb1746c18ae1e26b6038482270501f795c10b81e498847955c43dc303088a929cc4afb7187091d5e2d941f2ccd20aaaaa786b2b78b7f73e7691828594c61fdf87615b260c64c958e00fff368682b64cab1c49192e05bd084dd1ce534ecffb03aa89e6fda3f1e315f6d4655d1057ec20cda1a62ed91d66c9007
#TRUST-RSA-SHA256 73c6811a05cc672899892f88097a90c4e8a3a6f90f37a97008937bde02998817a2503d69d07ed9106bae8be30ca92c8e5ec86a1d6f033cb19d28a7e8fa5bb0ecd91bf1ea536748e889b56a8687c3494a13f3c9ee1cef3e5e45c7a37600c8c7eef21e0a2dae1790b1041f3b1b946bd1a208a4ccd36c5ea1d799362030b19770fd7e6bbf556e41dca009524010ab9ba6045e1677ea243137d4827465a7533ac027f143e8ee38874d57b1eb14f49fb64f23ff176b07791e3bfb71ed4b2df3a01f8767a94441b250f09de40831737853f3b9fe9adc91128cac0665645832d2463872197f4a2641af3cdf1de0b493800eaedfecac9f36d16a27ad137fdb6ddd2c4d21a207a9796b43a5a9e3822fe454669da73e650fa47feeffcbfd30d565d23da97f311bbd6a542f5a6b900ffd3a059815f621f050bca68e6b92e64286b8e1bf2aa5428a3470aea473482f88e5e5db9c92e50712eecfc7d2095e016c4d1ef5658337a273d4539a4d1b94f2159e3a595c728460acf25c9576980280899288cc5ad29c1b8a0c0c5dc2777e24f0bb4294012b4fcd4d81a94e5f586377a12dbbee65ab12acbe558d377c305a90007fb1e252b19f57eadd6b415d18c74069557d3bea5928989701b2fde7526e775a1210fd614467d8cab225a63573f566d3df419ba4cdbd612066ed72c340dc25adf52c9f2024f1662c669497f409445ac3551b448c7feb
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155734);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/09/28");

  script_cve_id("CVE-2021-1620");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw25564");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ikev2-ebFrwMPr");
  script_xref(name:"IAVA", value:"2021-A-0441-S");

  script_name(english:"Cisco IOS XE Software IKEv2 AutoReconnect Feature DoS (cisco-sa-ikev2-ebFrwMPr)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS-XE Software is affected by a denial of service (DoS) vulnerability in its 
AutoReconnect feature. An authenticated, remote attacker can exploit this issue to cause a DoS condition by exhausting
the free IP addresses from the assigned local pool.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ikev2-ebFrwMPr
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0ab6fc3e");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74581");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw25564");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvw25564");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1620");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/30");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

var version_list=make_list(
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
  '3.11.0S',
  '3.11.1E',
  '3.11.1S',
  '3.11.1aE',
  '3.11.2E',
  '3.11.2S',
  '3.11.2aE',
  '3.11.3E',
  '3.11.3S',
  '3.11.3aE',
  '3.11.4E',
  '3.11.4S',
  '3.11.5E',
  '3.11.99zE',
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
  '3.13.10S',
  '3.14.0S',
  '3.14.1S',
  '3.14.2S',
  '3.14.3S',
  '3.14.4S',
  '3.15.0S',
  '3.15.1S',
  '3.15.1cS',
  '3.15.1xbS',
  '3.15.2S',
  '3.15.2xbS',
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
  '3.16.8S',
  '3.16.9S',
  '3.16.10S',
  '3.16.10aS',
  '3.16.10bS',
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
  '3.18.9SP',
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
  '16.6.9',
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
  '16.9.7',
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
  '16.12.1z1',
  '16.12.1z2',
  '16.12.1za',
  '16.12.2',
  '16.12.2a',
  '16.12.2s',
  '16.12.2t',
  '16.12.3',
  '16.12.3a',
  '16.12.3s',
  '16.12.4',
  '16.12.4a',
  '16.12.5',
  '16.12.5a',
  '16.12.5b',
  '17.1.1',
  '17.1.1a',
  '17.1.1s',
  '17.1.1t',
  '17.1.2',
  '17.1.3',
  '17.2.1',
  '17.2.1a',
  '17.2.1r',
  '17.2.1v',
  '17.2.2',
  '17.2.3',
  '17.3.1',
  '17.3.1a',
  '17.3.1w',
  '17.3.1x',
  '17.3.1z',
  '17.3.2',
  '17.3.2a',
  '17.3.3',
  '17.3.3a',
  '17.4.1',
  '17.4.1a',
  '17.4.1b',
  '17.4.1c'
);

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = [WORKAROUND_CONFIG['ikev2_auto_reconnect_enabled']];

var reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_NOTE,
  'bug_id'   , 'CSCvw25564',
  'version'  , product_info['version'],
  'cmds'     , ['show running-config']
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
