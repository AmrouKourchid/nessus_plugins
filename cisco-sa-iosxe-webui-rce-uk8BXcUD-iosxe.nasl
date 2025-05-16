#TRUSTED 51173f092af2dadb2c84f1c54639441add7b910019e6c70f7f9bcc445f347c73cd77583db8704c99dccf49c396d86ade82166db1d86bf6b556c27b78ba735283419a7604dd308d27d76489572b21cb0eb41285df708013866580d425a4c7f5e954b8f6fc68328c7511ac18cf6ff721b4d49e872b1d8d227aebae389fad39dd001bf03bcb168575978b3f3173fe87ad78381db7ef59c5486fd62d3025bd65d009f59a49ada05846de6c23db26841c782511bbd18d19db20fa39e93d3d72a4aa04ae653e916ba9e73026d0b7921d6bf2822586b8b7c6666f7d723818454f53e4dfc9b453964b0708349129284262537f38a2e098762cd8fad9086902a4e23ce5fe6ff9f58b763650d2c7ff2b6171628cda5cc80e05f254668429e83e46217a8b2129bab256620bfe8a33989b9dd40220ffdec06a16383e865683ad42bd76ceb3a3c2fd56fe4983286f9fd8a4e4302e00d13e63beff9d879abfca46a5d5d05ad7597c270b44fda9540a81edb281d7fad63b1dbeb7f433b4ff10b57463aa474a69e97fc68ec32adc95001bef6453d8805de03f7c6ebe11773a866d952ccff59441fcae97d75ace4b0a47455017ec3e8d92f739e531cbab0155a7916f2d0bfc751a2280b7c90704f5aaa48c3fc14cce27debc45b06342c18bcf7d0860e6b0b568335679f8d19ec2b17433fc18b839ddfb4256951751c938243fcf99ac8f4dfbca6659
#TRUST-RSA-SHA256 60448b33b781bc2811879b041d0b75255edc938c300ae715b9c7c011405492bbe14e848ddd00eda645a10f579daebda39fab63bed0164ab2b9a7a36211a0d6c7648e15fb86f626a362ea06c30bda9c923c3046c1180ccab0e45e9192a8ee1deb9ea47ea03749cb7fc9d47e10e26dd435be90a6a1c504baa23404e76a86a50d93bc4f3271b8d38af1a700153d5c7b6a3992e99298859d1f52d24676780b41fcd7c6c0582c859975df35a28697baacde811e2399185c98e7c8e30c30cd8585809ee992834ca8d3ff3cdf9f18e65e201cc13fbb83300b05daa4dded6a2ead05c82f35d480d07be351975e6dc85b0831cbfbf5092edfbe6699587f0e1a6b85986fc55fd47e6e65e1b919920a113f9e862d607f7e905bf71cbd6030984fb14b0de84f5d9f9b9742409501ffddb48563bd78dcbbc439636842def27ba9c773a56afedb1e00ea6a2e9160357384f8eddc1ad1a93dffbba78544ca66816218971a5b631f73f0c46a8867f6f94f8c760db53d4d0fb6549d70b6e7e19133966ff8691d832b1afad0749865b25fff11a80f154f609647f3a373721bd2f208c7e28b522f44754362f055fa0535f2ff82d8ff63f650bdac2a37dbb0dd5e7ecadf08e1f8ce0ef160d6d1427b4431f389a5b819a6bf26a43d2b35598fbf86bd0495f236edf143b877eda072735dff86c5d31ba33fba35e1b55f5054729f44ae01786c832a11b715
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(137182);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2020-3218");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq01125");
  script_xref(name:"CISCO-SA", value:"cisco-sa-iosxe-webui-rce-uk8BXcUD");
  script_xref(name:"IAVA", value:"2020-A-0239-S");

  script_name(english:"Cisco IOS XE Software Web UI RCE (cisco-sa-iosxe-webui-rce-uk8BXcUD)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by
a remote code execution vulnerability. An authenticated, remote attacker can
exploit this, by supplying improperly validated input, to execute arbitrary
code with root privileges on the underlying Linux shell.

Please see the included Cisco BIDs and Cisco Security Advisory for more
information.

Note that Nessus has not tested for this issue but has instead relied only on
the application's self-reported version number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-webui-rce-uk8BXcUD
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?166cf8b9");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-73388");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq01125");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvq01125
or apply the workaround mentioned in the advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3218");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/05");

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

version_list=make_list(
  '16.9.4c',
  '16.9.4',
  '16.9.3s',
  '16.9.3h',
  '16.9.3a',
  '16.9.3',
  '16.9.2s',
  '16.9.2a',
  '16.9.2',
  '16.9.1s',
  '16.9.1d',
  '16.9.1c',
  '16.9.1b',
  '16.9.1a',
  '16.9.1',
  '16.8.3',
  '16.8.2',
  '16.8.1s',
  '16.8.1e',
  '16.8.1d',
  '16.8.1c',
  '16.8.1b',
  '16.8.1a',
  '16.8.1',
  '16.7.4',
  '16.7.3',
  '16.7.2',
  '16.7.1b',
  '16.7.1a',
  '16.7.1',
  '16.6.7a',
  '16.6.7',
  '16.6.6',
  '16.6.5b',
  '16.6.5a',
  '16.6.5',
  '16.6.4s',
  '16.6.4a',
  '16.6.4',
  '16.6.3',
  '16.6.2',
  '16.6.1',
  '16.12.1y',
  '16.11.1s',
  '16.11.1c',
  '16.11.1b',
  '16.11.1a',
  '16.11.1',
  '16.10.2',
  '16.10.1s',
  '16.10.1g',
  '16.10.1f',
  '16.10.1e',
  '16.10.1d',
  '16.10.1c',
  '16.10.1b',
  '16.10.1a',
  '16.10.1'
);

workarounds = make_list(CISCO_WORKAROUNDS['HTTP_Server_iosxe']);
workaround_params = {'no_active_sessions' : 1};

reporting = make_array(
'port'     , product_info['port'], 
'severity' , SECURITY_HOLE,
'version'  , product_info['version'],
'bug_id'   , 'CSCvq01125'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
