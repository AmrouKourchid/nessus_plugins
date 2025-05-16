#TRUSTED 3b6cad0cdbcb54935b083861dc4e76bdd0141fd8a7325bb21285c944ada4504fde65533c97adc59350386b62067602ce8485d1e6c7f237bef4dc0efa74a8b200ab1b75354712a9e1159cab58bacc4102c932e5bd6aeb0e5e0a5e4b91a62fadb58aa734616670026d028199c8c4320822bf8f75362a3e7f092d8d69507018132d7706803ae1afd53571a68118a56732cebe5c951064f37928bc3ae5f1604c9663762ddc7c2f9ddc8a0fc42da3e2a8e351106258a6810334ff8e669961e341bc1195748042c4fe781ca2b620df15c7cf0ba7441481510b04866269ef36c127064b57a10191ac9870c4911a9d902caf0454989829b3296db475aaf4b355868f757616e56d0e41019b279debb738935ab8addab28c435c7a35ab94eadc19f17943f1fde14559fe4b415140c78ac5201d45671fa0d3192bbe10a97873ea1b1c1ca5cc80b2405edd2ad61b9dca6d67e890b4780fce7a15ffba4aa73f6a50ac321ab584a3283ca3f0cefc65f7c0902ea2c9428accf02d7c3821a19fae67f4018fb6fc277582b31d3f7193af736cfa07e347cf827896b01d165a19050ef37409abcbbb3f6a049a350c2eab2695955142b6a33f6f6873f5bc1f6ab7e2b27792f4ee843703b5f276afb51df62837c5790cfe33bdb885ef7ec77d186fbeb99f3153238e0039c845b30e3431a8789f3870e89d45d442593c4115abcc8386f04e96562e9c858e
#TRUST-RSA-SHA256 6b71ecf91e6f825466932839b8b4e518865abb8bf59f1647920ca0fb864fed40d9ecef8cbbf08d07d9d58ba792f0bf0c39227afa1d5a0c5fbf3aeb9068aa4796f39c61ad6800e65adfa08d952b66dc5ea74d6abf484574a7d2559fd2ab71b86038cb7fb51067a2c014a0310526e94c86107c5a2f5b010d14dec220be4f18b44d71e90be6e6403b842b0319c5e862b0a1a41e0b50ff241bd30f606d08809d73dafbe98b43a85631bb09a63690c81fa170f07716b7137538fac7b090a8aee6e078216f651aa248c771d5e932c6bf95d21c3531f5a11ca70cc352f7c5d1c59f036d52c92072a99e59163cd8ec357a61be82facfc69beb9e76bc70fc271ef7a1f736c07bfc6b6c76b6daa9dbe5087f88d374518438cb1aaa612ddc62dfcbcfe45b43eea8ef2c1bbec5e3b0dfbefd9746ba6388bbdd53fb0a0169de6ccf9fdf1ec096c0cd2b5d1ddc04b784a1d58f484bea3071980a9214d0d14d4defcc621d2b330deb9cfc70ed93cee26ea0ada22313f63690e32c0a2c1824769b290d5cdf0b295407c07f2f694956dc8470f2cb5a9b39eb404fd256524b71fc12a1c3e3b076723361067e9cc2c4e486a7b699573690eef7a987db96de8d29b9ba7a7ae7480c07a5fcab4896ae3379a749e19d0bf16a489247a38f096e8369b7fe2ec7a2aa8f73a2c35f919f83286a55751a8dcb76914defaadd9b9b3104dcc560951f82b0b57097
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(132033);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2018-0186", "CVE-2018-0188", "CVE-2018-0190");
  script_bugtraq_id(103551);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuz38591");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvb09530");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvb10022");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180328-webuixss");

  script_name(english:"Cisco IOS XE Software Web UI Cross-Site Scripting Multiple Vulnerabilities (cisco-sa-20180328-webuixss)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by multiple cross-site scripting (XSS)
vulnerabilities in the web-based user interface (web UI) due to insufficient input validation of certain parameters
that are passed to the affected software via the web UI. An unauthenticated, remote attacker can exploit this, by
persuading a user of the affected UI to access a malicious link or by intercepting a user request for the affected UI
and injecting malicious code into the request. This would allow the attacker to execute arbitrary script code in the
context of the affected UI or allow the attacker to access sensitive browser-based information on the user's system.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180328-webuixss
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4c03922e");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuz38591");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvb09530");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvb10022");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s) CSCuz38591, CSCvb09530, and CSCvb10022.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0190");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/13");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Settings/ParanoidReport");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');
include('audit.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

vuln_ranges = [{ 'min_ver' : '16.1', 'fix_ver' : '16.3.6' }];

workarounds = make_list(CISCO_WORKAROUNDS['HTTP_Server_iosxe']);
workaround_params = make_list();

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCuz38591, CSCvb09530, CSCvb10022',
  'cmds'     , make_list('show running-config'),
  'xss'      , TRUE
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
