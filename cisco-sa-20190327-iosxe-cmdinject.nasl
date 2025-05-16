#TRUSTED 49eca267fc19fde3b1a6139dc69a51e84221676dfb47c28cc71b62e9e8f114fffdf09f5abc43a7ab30b1ebddc2a99229d0c07e3d38858e6d715ace4e7892e1cf0e9e5fff36d74df00bfa78ad2174aa0ade054c9565df759631d326b76fcac952e19bffef628070d7b4048b636a98aeb204c7296bd1a4c46335227315b1b2516244db6a8f099adaadd081fbbd5984d71577964b0b7a95694957b786852689fa4a94885597ab9a4ea5a046708676ab26ace2d158b9f82511a891cdd14058e06485394466fbd23b4cdba22e4bd8c77d5441e1e0533869734fdd6cc0dc309fd6a7608ebf3db089351ad877c694cbb7de1efd7bb5d57cafc6925b83d5e74422613757e251f6803caed6898bce6b7e36e8e94abab0af700ca21504e372089a21a601b58ff8670101068a8d2fcdf319973dd9c99c67914cbd62e09f4b64a3e1abccdca4b33d425e1808480cd2954208486eaa02f9b817f2aa1d9672e15ce114f3cb79420980794e14a01aba22d0ce544a6dab549719223375770db3fe3840015cbe487a63dbed36c3f56ee9102fd9bb37831a699e8d4fb90fa20a46b6192dc9ccbbe8bc2811cf6081ca053a3fba9d210950f57deaead3cab152f2e90120efdd81e0468605f5c8978ecf2978ef0909498898d7c3be91e258cae96aa82856dc57e96a2354c1b63286f8ce05a7cc3511d8e7bbc3472303b5b73950526c3cdfb07a0befa7a5
#TRUST-RSA-SHA256 96609196308d35e60571581be5afeccf2fbb18b9abed0b7a4e9a156be86a6b236e7ade4bbe81f0e68ae3779a8c59f16fc060978d5c33b5a88245fa8af2e1e3ba2742a8fb0197d02d7502d69c9dcc0b0b77aeeed2f58c8512121aeedbf5f9a4e55ca90925fd55a05bce86895da6225acbce9aa3dd4a23e4830f3209bd0ecca6e6f221a7aa81c472f04da45157e213c38c11af60175db708c4d5367138750d3a8651ade3b7299dae0b4ef25cc30fd83ad1e6f80e9f3949803348600715da125284779b3176dee2e6cb1612541d303b948d4d80ef7e87d238ab7e5049d39b6488df5eb17b3af100baf2d5e53e1d4c7dd2e189e78e19fcd7ccaf55057e91b03f9d9173345cf55c6573e3323d5f7a633cda7c871600dc1ccfeab526a9df4836cae247bedd88087821a17c19878fba92f56c598026b63ab3d2839759c5d4ac4df74bf384871334377ecbf266117f94f6ea586979b296e809ad72a48e86c4ac0ffd29413091f74e033aa589b76f4d04cb25b4ee164b2509dd87f89f19d4ed35f28232b8dc249cce3a1af2f562907db1712180bc7a8e97ac47321e9cf7f98461b575c7ea5ce7b9caee33203646933a69338c3262ff1fbe9a0bd0d546842093ba364eee91351bd9d07c33260869a9abfc50a9f3859b6b4dd8b77a0de8b3839a787ae8be5c65aa7513ad90c4e877193a7808c01668f1b2af3c5d5392c0e7e99aa3cea4453d
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(127913);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2019-1756");
  script_bugtraq_id(107598);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi36805");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190327-iosxe-cmdinject");

  script_name(english:"Cisco IOS XE Software Command Injection Vulnerability");
  script_summary(english:"Checks the version of Cisco IOS XE Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a vulnerability that could allow
an authenticated, remote attacker to execute commands on the underlying Linux shell of an affected device with
root privileges.The vulnerability occurs because the affected software improperly sanitizes user-supplied input.
An attacker who has valid administrator access to an affected device could exploit this vulnerability by supplying
a username with a malicious payload in the web UI and subsequently making a request to a specific endpoint in the
web UI. A successful exploit could allow the attacker to run arbitrary commands as the root user, allowing complete
compromise of the system.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190327-iosxe-cmdinject
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?248d1150");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-71135");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi36805");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvi36805");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1756");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/20");

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

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info, version_list, workarounds, workaround_params, reporting,

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list=make_list(
  '3.2.0JA',
  '16.8.2',
  '16.8.1s',
  '16.8.1e',
  '16.8.1d',
  '16.8.1c',
  '16.8.1b',
  '16.8.1a',
  '16.8.1',
  '16.7.3',
  '16.7.2',
  '16.7.1b',
  '16.7.1a',
  '16.7.1'
);

var workarounds = make_list(CISCO_WORKAROUNDS['HTTP_Server_iosxe']);
var workaround_params = make_list();

reporting = make_array(
'port'     , product_info['port'],
'severity' , SECURITY_HOLE,
'version'  , product_info['version'],
'bug_id'   , 'CSCvi36805',
'cmds'     , make_list('show running-config')
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
