#TRUSTED 40cf98c48d6878591b42938f605f502201196e613cc6edb2b8b6ce42939e833c459f4cb9d070437586d232f77e9e9ec0c2e2d76ca0337ec0ee6a1b50c2bfced61859375c6d9fa4135e5b5b5335bd5365dd466e16215dc2871ac1769783c4161eb6915c3615e8b1fd71af326bd6d522d5a5dd94fd9abb15386a0b6bc86f6aef95440aa761744a086861654cf6a45e23977fd2f4ec04793211c6ed36fcad90b555f72e02cf3e75fbb8542f5e1c526330eaf38c692a20b8eafecc7047aebd3a7e89b7a85eba3545e687bb8259352c3f4abb480b4316bbbb8db5443ff10472915dc301d30e7d1dd03ccbcd961a775a7aefa98ff9c24e960af6b672964128489bab96fc0bec852a162f016f130151c0588a0bf11676434678cb555d5fb9461e42573e5873d0097ad50f089a55481332aba71d83534f32a331553bd2ef296402082834b4054d63a116a7b35e83bd2ef337c9e7b53b2135f2765baf883262e0907ca678790383b72fc4ee76f9103ddc1443bb61e503f8ac7b7b0676ff786daebffd04b662b212ad32890738a81617db6ca41dc0230c9d56e22a1c460c9d52a241db66fc14c2cc05e4f50544d5fb99ab4daea140d300d24aeb15ec18dfcb45f4bf57be55bdbf167cf25ee1f39fe0a956e3887bc60d1851523af6dd404a277a14d2fcc51b2a96199425a5309d245a58702af97e6f4a9fd975a253e4496c019c4dfebc894f
#TRUST-RSA-SHA256 4c29309cf1f49621adc48ef97c7c704e522808608a00fd9102c8fb54c6044caf520ab35042e03e9623e07cea0d1c7d28e493e3e0ddb1b3d0435f18c89f44ab6e573c9ee0d578d2b5dbb540f2e6e08b7bfbb30b780cc73a3364782c02c2139ff5284bd3abc47bf1d42a1f2a02243b60f6cb89753d8f3f1dd1923bfb0c0f4fdfb2caeecdeaae138bf74a83d669d6cdf92bdac72d7149f2a28402c7630ef03a2af512b89dc28efeb9c40085d646e6b13124aff394f9e838d350b4b91b25f4ffd6d9877f984b484949998e454141977440b1757267c6f9e1f7869cb523353616e5eacdb9ade609304d57214c0517fa44e395ffbaf79d8935c50c8616a8cfe04d80f017228f4bc4c83d5b42d359404ef671cab5913d7772c8212749f8277dfde914f0b1ee8a7aaed04f2ce917a3c1292847fd2a558d51877e99d597cd6c221ad387e911f4c699791f2a9c704adc351b472d314312b6bd932654803b73cfa0bc235f981cf5a455cd23429e8c02b2a6ef414456b30c6ddcdd41c7aa735792ef262495649101fc3df32ce270a9dc5c499c6631878d894df5d868372a332acd447f086daaf8f3ea8ed95a0c370d3aa0172868da66230869cc62c80fc5548ddd872816bb4d088d91c6710e87dacae89562b02e5e55947e39bf156652acca531d42c2e2e0ca88f09601a9037c15ceb6dafca9a791bf9ba86485356a1f6ec5be225b0c546bb6
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97944);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2017-3849");
  script_bugtraq_id(96972);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvc42717");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170320-ani");

  script_name(english:"Cisco IOS XE ANI Registrar DoS (cisco-sa-20170320-ani)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS XE software
running on the remote device is affected by a denial of service
vulnerability in the Autonomic Networking Infrastructure (ANI)
registrar feature due to incomplete input validation of certain
crafted packets. An unauthenticated, adjacent attacker can exploit
this issue, via specially crafted autonomic network channel discovery
packets, to cause the device to reload.

Note that this issue only affect devices with ANI enabled that are
configured as an autonomic registrar and that have a whitelist
configured.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170320-ani
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?206d164a");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20170320-ani.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/24");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

ver = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

flag = 0;
override = 0;

affected_versions = [
  '3.10.0S',
  '3.10.1S',
  '3.10.2S',
  '3.10.3S',
  '3.10.4S',
  '3.10.5S',
  '3.10.6S',
  '3.10.2tS',
  '3.10.7S',
  '3.10.1xbS',
  '3.10.8S',
  '3.10.8aS',
  '3.11.1S',
  '3.11.2S',
  '3.11.0S',
  '3.11.3S',
  '3.11.4S',
  '3.12.1S',
  '3.12.2S',
  '3.12.3S',
  '3.12.0aS',
  '3.12.4S',
  '3.13.0S',
  '3.13.1S',
  '3.13.2S',
  '3.13.3S',
  '3.13.4S',
  '3.13.5S',
  '3.13.2aS',
  '3.13.0aS',
  '3.13.5aS',
  '3.13.6S',
  '3.13.6aS',
  '3.14.0S',
  '3.14.1S',
  '3.14.2S',
  '3.14.3S',
  '3.14.4S',
  '3.15.0S',
  '3.15.1S',
  '3.15.2S',
  '3.15.1cS',
  '3.15.3S',
  '3.15.4S',
  '3.7.0E',
  '3.7.1E',
  '3.7.2E',
  '3.7.3E',
  '3.7.4E',
  '3.7.5E',
  '3.16.0S',
  '3.16.1S',
  '3.16.1aS',
  '3.16.2S',
  '3.16.0cS',
  '3.16.3S',
  '3.16.2bS',
  '3.16.3aS',
  '3.16.4S',
  '3.16.4aS',
  '3.16.4bS',
  '3.16.5S',
  '3.16.4dS',
  '3.17.0S',
  '3.17.1S',
  '3.17.2S ',
  '3.17.1aS',
  '3.17.3S',
  '3.8.0E',
  '3.8.1E',
  '3.8.2E',
  '3.8.3E',
  '3.18.0aS',
  '3.18.0S',
  '3.18.1S',
  '3.18.2S',
  '3.18.3vS',
  '3.18.0SP',
  '3.18.1SP',
  '3.18.1aSP',
  '3.18.1bSP',
  '3.18.1cSP',
  '3.9.0E',
  '3.9.1E'
];

foreach affected_version (affected_versions)
  if (ver == affected_version)
    flag++;

# Check that ANI is running
if (flag && get_kb_item("Host/local_checks_enabled"))
{
  flag = 0;
  buf = cisco_command_kb_item("Host/Cisco/Config/show_run_autonomic","show run | include autonomic");
  if (check_cisco_result(buf))
  {
    if (
      ( !empty_or_null(buf) ) &&
      ( "no autonomic" >!< buf )
    ) flag = 1;
  }
  else if (cisco_needs_enable(buf))
  {
    flag = 1;
    override = 1;
  }
}

if (flag) security_report_cisco(severity:SECURITY_WARNING, port:0, version:ver, bug_id:'CSCvc42717', override:override);
else audit(AUDIT_HOST_NOT, "affected");
