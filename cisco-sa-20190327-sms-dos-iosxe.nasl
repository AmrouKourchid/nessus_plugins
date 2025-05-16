#TRUSTED 481b33f8327d83bb02c904c5f084f6e2a0e7a27f08730eac368970a6743f88af64cb1a99396e46c52c0ccbdcd7d1dd7c9e6a607cb872450e4688eaf506d8c2d3ac70e0b499eb3324bf6af47461cf9437691ea2b4be0eb089f482a651d5af8a7aac32df3b3d9bf7658ca2bbb0d5a9d24117f1d265680600842fc11eefef7a61dcdfe5a89fc65704e5778549118c9d2e6ea634b3f6593ac7a39ddf5d896a6bf621f5dce1b146a1e0d31c4958886a43527d6ab4c7d4b32beb4cad5f27820eaddfc6c6af36213e97e79494bbf2617bb876b99053a3376dbae9c5108bfc92dcdfc8b9d1c72033511c6f0ed786f95ed7146caf006e354a485aba448b8ba8f670ec2f4fb21d17bb56d5db0ad947b40b24ac578a67fdae642548c5dfd8caf095755ebeb6f2e337d1de07b23d0c8a071f7379ea045be89a4108c0a742456ae5e9c2484b7c4d36f64d7a3422e919ea67dd4c89459cc71a78bcd886d8fd3c893898e5943891cd8e96d7fdfb8082967c2a82834378b008d835e26e5b148c28a2d838e212ea7844216230ac7c25f168d59f0996812f13a970ccc8ba5f2924c7f39333757fc23b97b353b2c33988f1a1cda86dba93b50b44b0d14050bb36179ce81eaf42927f85174ab2079ecff1043ec613221e5968a606db2782e16451da6d2031cbba327625ca70ef86bd91cdf64e3e4834e57323f7905637defcf13a499185a2ade7dc9779
#TRUST-RSA-SHA256 45d6000c6ccdf9b009898d0cea278d4437aa0531074db50bdaada0b1de60d7b41f8ae5b9a60a83f81096604e4c33551bfd0a681e4b7753a69419fbdeac930ff48689e9dfe75ac441366fdc536a114c610a33be9357cec8e4d3efa646091001af572a48c27f4be8820b04de2b28f38d6dda6facda9e2e8430d2d934ee9314e0195df64a22eb590e391c8e79d5be564e1ad1e212c22655f00086c2140a99e5e6355233181273f8e0b53372d9605cffebacd2002b7619a86308e17c004cc8e09f0a223325910240157aab322e7e177029ba68518bab1103c9ee22f9820517a1228424ccf7bf5e420eb39fb70802ac64953ddc09b8611db2cc190c4c65ca3750cb82f4e79b15a17103f4e110ef5c4dbdc8da71a2340da235561b0733097cdec6d68be5b4d24dfbf62d2dc4ecb3ff064204973fdc4161c32f415f0eaebf93d1cb189760249810ba71f58d9ea928dfaa416b08d53a9d0ad42f90c820611ed30384015f8f7b57a775762e252f3fbc73ddd5cf086063c6aab82093783b85b1b414f95e8e742bbc525612809b8e880813e8fdac736950e1a75350075d2a4703cace78fda4adf0339c53ed30edc56c0d217f6d665e3bf2eb02848275941f74ac4720d98ccfe6d524bbea118f1f2ba2daa510064734f082ea1f72956950944b5f761c781d661bc913a440877af3e30cb2eaad5ef4d908451f665f43f2cd2e038deb7a00ba29
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(128114);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2019-1747");
  script_bugtraq_id(107599);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvm07801");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190327-sms-dos");

  script_name(english:"Cisco IOS XE Software Short Message Service Denial of Service Vulnerability");
  script_summary(english:"Checks the version of Cisco IOS XE Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the installed Cisco IOS XE Software is affected by a vulnerability in its
implementation of the Short Message Service (SMS) handling functionality. This allows an unauthenticated, remote
attacker to trigger a denial of service (DoS) condition on an affected device. The vulnerability is due to improper
processing of SMS protocol data units (PDUs) that are encoded with a special character set. An attacker can exploit
this vulnerability by sending a malicious SMS message to an affected device. A successful exploit allows the attacker
to cause the wireless WAN (WWAN) cellular interface module on an affected device to crash, resulting in a DoS condition
that would require manual intervention to restore normal operating conditions.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190327-sms-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?22250072");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-71135");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvm07801");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvm07801");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1747");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/23");

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
  '16.10.1'
);

workarounds = make_list(CISCO_WORKAROUNDS['sierra_wireless']);
workaround_params = make_list();


reporting = make_array(
'port'     , product_info['port'], 
'severity' , SECURITY_WARNING,
'version'  , product_info['version'],
'bug_id'   , 'CSCvm07801',
'cmds'     , make_list('show inventory | include Sierra Wireless')
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);

