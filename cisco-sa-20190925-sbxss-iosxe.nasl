#TRUSTED ad02de314ceb6a29c6335cf2a2a1f5f25d87070770d87b783ca35a4a4d141ae74389d3108623d8505500cc809b54eea3bb15987df7b7175e6eb8df02f8421f63eba7f82494e9e9ec046e9dc72cdf0f51264d3ae59315c8f7324000a30f47b3d39f121ab095313462fc081404b9593aa301734bac1787923653ac5ce4e7e7955b057f39e725d3af5e46ef5bb42fdf7d0ca39265a57a50ec338494edd2b929a4662de49ed6fede46d048314a48158fd5fbb0e2ffb9253e93411003df6e9407385853affa6155086cf71512b0364f24187cb4c0360850498e5a2476e9640fba8ae55956c9955a175b0ebea4528574ba0330a8f07a3758ccc6886038dc828d9b5d77c1d3dc528ed7b388bfefd508bd938aa4e7d6986a87a3ec74ba7f2f4afe67677812553b29cceeff10b376338b9f5ec8612f56cc7fe74f6155d8fe563d82a1d84608a90a30475134bf943be659c4313686d3bdfbc0761f27b006f4303fe2d823f615d2ccd9f7f084b11a8a9a9c1ae9fafc27726346b79aa7166e5764a6bcf29a881a3532023d000839aa202cc1fa79fe3fa73b698a7c14fd8a1e583d46f5113ff33eae970be07ec25c14bcaf15692ffb180f74e23c5314f1725c8951dc37c89248568feb59e5f206a058d1a9d64e2102b03f3783fc442740c86fcbebf6b290a070634f1571c6d80a470ff9ebf1595da5360bf1b18c64f328d89fe59589091b28bf
#TRUST-RSA-SHA256 949dae3ebe76a6700fe5359c0664de1be77684d295c6031855d617d78ad1e2e0b00605edb8fa1381e63249d85e544ab86aece4059c03bb6624a6344c96105a6db914459678a7a6e2f277a5fb629864a66ab48d1ce039fa5e6a2fc993d181d7fe8310f8689632861d37d44c8211a3bf4307675063c81a9298aff06acd9ce952b1d053bdb3d959314b47bffdbdd5389728b86ca2ad03b600c4e69aca8ef62f8ace2407ad770a201cee97b5c144e497326465b02fbc2bc9fc859646a1be15c0f6b9e8eb45acff64370ebf21c94efc6bc559e6c2474d798744fe1b7018f1ac280adbe680dda95e961ce7cf2cf38885fdb9179c5d731764b1f4f60fc040f80df1c3722d9ada94471c6c16a8d7103b8f9bca7c78d6a2c56e940428fb4e3df7d35fd52a29650b77ed12dbeae10149d94cf52b0d241ab8fb161848af58c7d548156a5eb258bd3a9def8c58fa10dd4b8f7a2508ef3444f8b9cc4121c9cf2c3ef59223c8284232d5d7e09ba28b7a702ebeb9eff1c03af0b78188bd8ce72feee516b6c6ad3c23f57cb8a7b89bdc051fe7e4d5740b588435a3ca6841d13917414119c9e0a746e58e06018f57d5683ddcf1442480ed0d1e1e0d3fbafb2a088e58c063180bdb4cd604ad66d11faf61bccde9fe94defc5c680ce4ad391d9a37c47e18c4ff2ec4473a615cda14595482ead2e7f07544f11ff8e58e8f295fdb513e3bca188eb92215
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(129826);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2019-12668");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvk25852");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190925-sbxss");
  script_xref(name:"IAVA", value:"2019-A-0352-S");

  script_name(english:"Cisco IOS XE Software Stored Banner XSS (cisco-sa-20190925-sbxss)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a cross-site scripting vulnerability which
allows an authenticated, remote attacker to conduct a stored cross-site scripting (XSS) attack against a user of the
web interface of the affected software using the banner parameter. The vulnerability is due to insufficient input
validation of the banner parameters that are passed to the web server of the affected software. An attacker can exploit
this vulnerability by crafting a banner parameter and saving it. The attacker could then convince a user of the web
interface to access a malicious link or could intercept a user request for the affected web interface and inject
malicious code into the request. A successful exploit could allow the attacker to execute arbitrary script code in the
context of the affected web interface or allow the attacker to access sensitive browser-based information.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190925-sbxss
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5eb43f8a");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvk25852");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvk25852");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12668");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/11");

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
  '3.9.2bE',
  '3.9.2E',
  '3.9.1E',
  '3.9.0E',
  '3.8.7E',
  '3.8.6E',
  '3.8.5aE',
  '3.8.5E',
  '3.8.4E',
  '3.8.3E',
  '3.8.2E',
  '3.8.1E',
  '3.8.0E',
  '3.7.5E',
  '3.7.4E',
  '3.7.3E',
  '3.7.2E',
  '3.7.1E',
  '3.7.0E',
  '3.6.9aE',
  '3.6.9E',
  '3.6.8E',
  '3.6.7bE',
  '3.6.7aE',
  '3.6.7E',
  '3.6.6E',
  '3.6.5bE',
  '3.6.5aE',
  '3.6.5E',
  '3.6.4E',
  '3.6.3E',
  '3.6.2aE',
  '3.6.2E',
  '3.6.1E',
  '3.6.0bE',
  '3.6.0aE',
  '3.6.0E',
  '3.10.2E',
  '3.10.1sE',
  '3.10.1aE',
  '3.10.1E',
  '3.10.0cE',
  '3.10.0E',
  '16.9.1s',
  '16.9.1d',
  '16.9.1c',
  '16.9.1b',
  '16.9.1a',
  '16.9.1',
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

workarounds = make_list(CISCO_WORKAROUNDS['HTTP_Server_iosxe']);
workaround_params = {"no_active_sessions" : 1};

reporting = make_array(
'port'     , product_info['port'], 
'severity' , SECURITY_NOTE,
'version'  , product_info['version'],
'cmds'     , make_list('show running-config'),
'bug_id'   , 'CSCvk25852'
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
