#TRUSTED 6d4f0e77e78343d92cbb736688da7cea5536c4d40a33852743ffb4d092181ef45481c256e798e3a72a8ebf8639a4cfe368a8f5b9a3943091c44343839add99e11ed886eb2ea6e8c25056b1af88dd269c4c2504164156b669727ba7b9ff47595177ec9042fd22d35025a5dcdf724a3d3472ddeabceae7dde83bba42bfe7fa34cf488683939d12138a99a44d3d7cffe6d016c897be19ba3de83ab54ed735281d5177224139c9f7a974a7a84edad57ba5533c7a5eda767ed836efd3728d3cecae7ba34e851e1a90bab83f0a6f655439a92b4ba1d06c22dd6cc04bc3e044d87b13710b846aed266512278b19e14c908621199d97a69661f3084bd0fc9464d6ebe2949e79d7b9af9361b5305a3e1a6e7ea3b3bc8b4c11bb7c6c8a25bb77e940636934e8b88c5e3983e12bd49010b2e4f7db23614753dc4f62e3d3b657461f16c45728cf0cee9b4473328229ff67aa41ab76c78e166ea57e7d66746fecbb4fb6c909aa53c4d7fd6f82058b14e0042633a8d2a55afa038de228852d67e248ae785e2912438d6ab7613fe9fd3e660ca3e2e2877599b41563de4b2fada9ac8d8618ef51e187691ee0dedaffd58074e60e15cf0ff588eb4b9e3d3f94aaac91896376257167318c00e34af5f0779d64fea8d4369e5a556ab497a887c06e421a36b1770d8e47ed07410b2d4dd3583f66c2f4abbb826dd1677a1cf04b2d80b936bb6a9a4601f1
#TRUST-RSA-SHA256 878fac175307dd71ab5210fd60043c496964d5f3bf85910d180119a81ee49b40ca19aad876abf796917d70e282b1b79400fe7312bc9a20796e5717d1b678a8d104e8cf34cebbd2cb4ad0af538ebb69e94f43fdb94745453be44092a5436c5c442a06d65720846d8345ce0f2d6b1015379d6c6dca64d7ea13b4c83aeb4d165b72e5715d5dc777e55b303ddd674e81a198b2aefc797c3d534c702562823fd331c0cc0f7eddd3b32dc8445a972d1fd52d2f592ce2b3ef52eec0441398a5ed3d527a06d112defe410618ad9791d19cfd1626b3d5c7055ec8c5d3d3815d0039bfe2813fdbcb798c8314cd853eb97e4637c672e5663a410823547e577f66899258a02f1d4a58485b379b2c45c412c0bb7fcab8bd999c7090ef915952c0258fcb050e96c12a5681a10c44636cd856c6b9e4de97ae12fe99f22ab6cfac923cd5194470feb8bdb06497a3fc8bca79ecf41885031d112e56880c8f8e3d9f31be6a326bbccd920f7f68305f5c03d17e609347f708f223110126b328781679f47cef356eef2aa3f4145ce303848061a545412033ffeca362aa2533a211993ffe74808952c0b35e6dc04cb1de0515fea60fd2900a1be536d3de6ced7ee20428a6965931875cf68722845c454a0079950fe2fd464dbb91662707358f572f18ebfcbe037ecef840ff54b4d86d9f5ccbc89c196129b6af10dbdce861f870ce39d7b2fe66b3c62b79
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(128051);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2019-1745");
  script_bugtraq_id(107588);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvj61307");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190327-xecmd");

  script_name(english:"Cisco IOS XE Software Command Injection Vulnerability");
  script_summary(english:"Checks the version of Cisco IOS XE Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS XE Software is affected by a vulnerability that allows an
authenticated, local attacker to inject arbitrary commands that are executed with elevated privileges. The
vulnerability is due to insufficient input validation of commands supplied by the user. An attacker can exploit this
vulnerability by authenticating to a device and submitting specially crafted input to the affected commands. An exploit
allows the attacker to gain root privileges on the affected device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190327-xecmd
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e8ea3e96");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-71135");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj61307");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvj61307");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1745");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(78);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/21");

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
  '3.18.5SP',
  '3.18.4SP',
  '3.18.4S',
  '3.18.3bSP',
  '3.18.3aSP',
  '3.18.3SP',
  '3.18.3S',
  '3.18.2aSP',
  '3.18.2SP',
  '3.18.2S',
  '3.18.1iSP',
  '3.18.1hSP',
  '3.18.1gSP',
  '3.18.1cSP',
  '3.18.1bSP',
  '3.18.1aSP',
  '3.18.1SP',
  '3.18.1S',
  '3.18.0aS',
  '3.18.0SP',
  '3.18.0S',
  '3.17.4S',
  '3.17.3S',
  '3.17.2S',
  '3.17.1aS',
  '3.17.1S',
  '3.17.0S',
  '3.16.8S',
  '3.16.7bS',
  '3.16.7aS',
  '3.16.7S',
  '3.16.6bS',
  '3.16.6S',
  '3.16.5bS',
  '3.16.5aS',
  '3.16.5S',
  '3.16.4gS',
  '3.16.4eS',
  '3.16.4dS',
  '3.16.4cS',
  '3.16.4bS',
  '3.16.4aS',
  '3.16.4S',
  '3.16.3aS',
  '3.16.3S',
  '3.16.2bS',
  '3.16.2aS',
  '3.16.2S',
  '3.16.1aS',
  '3.16.1S',
  '3.16.0cS',
  '3.16.0bS',
  '3.16.0aS',
  '3.16.0S',
  '3.15.4S',
  '3.15.3S',
  '3.15.2S',
  '3.15.1cS',
  '3.15.1S',
  '3.15.0S',
  '3.14.4S',
  '3.14.3S',
  '3.14.2S',
  '3.14.1S',
  '3.14.0S',
  '3.13.9S',
  '3.13.8S',
  '3.13.7aS',
  '3.13.7S',
  '3.13.6bS',
  '3.13.6aS',
  '3.13.6S',
  '3.13.5aS',
  '3.13.5S',
  '3.13.4S',
  '3.13.3S',
  '3.13.2aS',
  '3.13.2S',
  '3.13.1S',
  '3.13.10S',
  '3.13.0aS',
  '3.13.0S',
  '3.12.4S',
  '3.12.3S',
  '3.12.2S',
  '3.12.1S',
  '3.12.0aS',
  '3.12.0S',
  '3.11.4S',
  '3.11.3S',
  '3.11.2S',
  '3.11.1S',
  '3.11.0S',
  '3.10.9S',
  '3.10.8aS',
  '3.10.8S',
  '3.10.7S',
  '3.10.6S',
  '3.10.5S',
  '3.10.4S',
  '3.10.3S',
  '3.10.2tS',
  '3.10.2aS',
  '3.10.2S',
  '3.10.1S',
  '3.10.10S',
  '3.10.0S',
  '16.9.2a',
  '16.9.2',
  '16.9.1s',
  '16.9.1d',
  '16.9.1c',
  '16.9.1b',
  '16.9.1a',
  '16.9.1',
  '16.8.2',
  '16.8.1s',
  '16.8.1e',
  '16.8.1d',
  '16.8.1c',
  '16.8.1b',
  '16.8.1a',
  '16.8.1',
  '16.7.2',
  '16.7.1b',
  '16.7.1a',
  '16.7.1',
  '16.6.4s',
  '16.6.4a',
  '16.6.4',
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

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();


reporting = make_array(
'port'     , product_info['port'], 
'severity' , SECURITY_HOLE,
'version'  , product_info['version'],
'bug_id'   , 'CSCvj61307'
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
