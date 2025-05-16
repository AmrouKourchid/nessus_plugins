#TRUSTED 22dedbb8030d7be9997993e7806888931fba10d53aae4ee31da6b91aa351d4a28621f4cb1d760cdfbb0bea71954628f5881056b5b1c50f0f84a7e2bfc74330d7ef84bb880712c523f629de5d5ab9820ad7768cfa55f3dd28f1680d5668e1c5ff9bda2f1486434ffcf636d4a97c46e8764465d46c318af8441795daebb2930e09c8d4fc5e9093709c9f937c7874d08bb5f7bd470aad4faab63e799b82a74f750d0ae94bf3473e76f815ffef0b68a3ba413bd65abfc8d75187efecba3faddf70873a00a53921804f8509adac173e984ccc0a33f521448b088bfef64da90c21228e8a673c25cce8a1953359dfbdc3f5942b5abb519157c480fe3f3e0339febe85010c535a34a3081ae4fa034d02968d2332519601ade233c0ff23c480ab142b42dc9b9b42b9b05523abd1a5d5e265bb54521b05ed0d332db21e3d8bc5254a7fe7319ece072db87a776190d9cda233d31db369a55d05861cbd81dc2fef616b71dd80a0e40a5f787ad4146b0172e6a2066d85efe9f563c4fe11900d75833143311708b7f6a4c074f4613af176f148cb34451e7a5c4bebff0f852864a1b87ea122f050489f4c553923836dae557745bf6ddace96fb569d029ba93b67d0502ba028674ee2ecd2c446f28ba70c000c75893782ab4c196eaa21a874b8d36228196b59f7ed0f0790d48c30539f120e17d758776180e7ff09fe6164583f067dff9e28a5a9f1
#TRUST-RSA-SHA256 705ea8ac035bd7c859e848b128d501d9c9f2aab5bc8408ec1bf3cc3a6d0f4be5010c2c0039d85a562d7bbefd46d3aa514acbe8cb7addbdcc1eb5f9e04919dc493f66a08d4f0daa1c44fa43d246d4b300901fb059cb7e90c231dead00837a8f2208b5abdeeab87f1d3589626b3a4dd7593f2ba5d2ad285a9f374016c0d526baefa0c095b58acc080cbd42586f489bb3d54e82254bf7f1ddb77aa9a695cece3f4f69852cf36ac827822afd47efc88dd55aa7ca44ae5d6244b2d6deab9a42c8242b6f050725aafb50b00326011145f6e8f370b16415e739dffc97708f72f7ab1263aa0267ae127bceec99dc25492b47d8f6b0e96f28577e905fb0121490227fc1edf10b054a0d8d86f2944750b03dab845e8dbd9c1684d701968ae0899ee2cf4fd737139d6f9555b2bf970a649d34d40700e038e0f5392a1f2bc093af64802d30bf965aa361beba10ecd4fdb96d5648f1384fd388e84339591a21909e9ade1f5e0117a0a22f52e5aa98af3287943aa8f5a1ec6eea2b3665a56f4d76d542b6ed35a1e7515c41c6f81bf249f4568e3ff6b4bc0abbc2093a89b43f55881b7edecfe71779db04135bf92204263dfae26c361bff5c42d92e06b5c7a79bb087999dcde721aef3724c54e9a95a7cd6d96cceeca65c3ede018af05522801b28d1888d93011ffd3e8f1622e0bc37441f2e085ab4dfd542200d017d9385524e5e69db6c6a2f5f
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(127912);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2019-1753");
  script_bugtraq_id(107602);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi42203");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190327-iosxe-pe");

  script_name(english:"Cisco IOS XE Software Privilege Escalation Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is
affected by a vulnerability in the web UI of Cisco IOS XE Software, which could allow an authenticated but
unprivileged (level 1), remote attacker to run privileged Cisco IOS commands by using the web UI.The
vulnerability is due to a failure to validate and sanitize input in Web Services Management Agent (WSMA)
functions. An attacker could exploit this vulnerability by submitting a malicious payload to the affected
device's web UI. A successful exploit could allow the lower-privileged attacker to execute arbitrary commands
with higher privileges on the affected device.

Please see the included Cisco BIDs and Cisco Security Advisory for
more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190327-iosxe-pe
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?acb267e0");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-71135");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi42203");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvi42203");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1753");

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

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list=make_list(
  '16.6.1',
  '16.6.2',
  '16.6.3',
  '16.7.1',
  '16.8.1',
  '16.8.1a',
  '16.8.1b',
  '16.8.1s',
  '16.8.1c'
);

workarounds = make_list(CISCO_WORKAROUNDS['HTTP_Server_iosxe']);
workaround_params = make_list();


reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvi42203'
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
