#TRUSTED 8231bce74a68408ad12b53d4c26c6ccb2e830ae44ab41faaafc28822884647a4306b910cec9faa7faed3957ddf95518e9fee852930f5a0ec6a5201ee67d416f5772ffb4b2a7bf72655e41cbc8baaf12ada92557376b11944f14a9406ee387f37446784536531f02029152e3ec5b51d949d62a67065c78947bf5b04943f77ee74269aae4ca2825b7363625f738646d9d16fc69b4f82e754270301ad94faa9327493028612fe47a5707eb81f155a4506e83c9a4ad86b4f42826b802f43ff13abd1bfe579f4e280f06c4b11af0a776282571ce663c26e194e5975ff0caf532c9dd146ddbb6da61e9991998d0b48931b6cd7784546501b9743f645c28c3f953ebce2f4153613aab10ac0e2c314701fa74b803954ed2f0f85014b533fbf52506e40b85ec22514714b6edd4473c5b583c2cd420efbad0ccbf71b6aa5e099484d7a6eb5e03c7fcf379dddfe24882808ee41a7ade422050399c083260514cbad72892679948f39bd9ef26ddbe3f0399dde26908381c0205bf6f8021976ec44d0c1e25c7d6703ab37216c1d86416e642ea79a5302212fc5b4c61be159120fe8068978912a25d999e1543a8d152305b760d9cc3f79c360263fd8bb5bcd7ef7323ab982df491366a22d617b404e1a086455db7d7a9873bea9f72313ada5c70a8655db21f332bc7ba9758cef3cd82b5e19278ee6a6f40131b753842c045ed7d98dd291a4354b
#TRUST-RSA-SHA256 28e160dca5c345c135636077805f3fa981ed032e0aaa776077fe0512bbaa622a4bab2ff42c8a6511fcfb855720c338d7532709e93f858af6a58877829be7cec7cbb624f8369a9da5d073cd6aa97618945d5c237cadda2aee31b968fe5badb2f71e056d4334654ab886c7472229fe8f727f54220875fc2a164d1d25c910b53b5c38f801ec9060c12adf2071d23bba683ce6ddd00224aebc0c2566db7b5bfcf472ebada39c2c148cae84bbbd8b3680d48e69d4ca5ed47fd74ebc4080acbc9fd2587ff46fc931c9fa2bac5661657924142d457644ac206c472938029ae48710070ed2e98f903d32daeea0232268e11bc3d702e5281e787db1ceca90bbf25f25ae5351685acb48f00d8d0529dc1ef0fd022fb5d4e5735ef8ee1b7d074328890e43ef36b93f43053f5d27d94d9dc51eff825e3e9bdee5cf3592009872427b67c9bb8912db71694da7993c0d6a2e82aad075028f1643672d5a5f42559891cf019138e0770627f100b6ef02ef59296540c2e92a8da53a7640bcc2c560dc823624d534f3c876403479559ca07fbb212ec5850aab469dd57c5d4f391469cd9b3d0e1801c8c7021bb7c08f5552c7c3f8efb6fdda1e7e2b2c9ca89bd6a1e7b1bf46af3106ae282545f7381d9fcabeb084badae0154b52bff9d908d81be5b28b3b2c7b0a427b625b079e9e6734c3c9c2f994755f5ca79df86e148ce3026c76c0098d9f9cbc85
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(126509);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/10");

  script_cve_id("CVE-2019-1593");
  script_bugtraq_id(107324);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvj59431");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvj59446");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvk52940");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvk52941");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190306-nx-os-bash-escal");

  script_name(english:"Cisco NX-OS Software Bash Shell Role-Based Access Control Bypass Privilege Escalation Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, a bash shell implementation for Cisco NX-OS software is affected access
control bypass privilege vulnerability. An authenticated local attacker can escalate their privilege level by
executing commands authorized to other user roles.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190306-nx-os-bash-escal
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b371e68a");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-70757");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj59431");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj59446");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvk52940");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvk52941");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvj59431, CSCvj59446, CSCvk52940, CSCvk52941");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1593");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(264);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/05");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Device", "Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Model");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco NX-OS Software');
cbi = '';

version_list=make_list(
  '7.0(3)F1(1)',
  '7.0(3)F2(1)',
  '7.0(3)F2(2)',
  '7.0(3)F3(1)',
  '7.0(3)F3(2)',
  '7.0(3)F3(3)',
  '7.0(3)F3(3a)',
  '7.0(3)F3(4)',
  '7.0(3)I1(1)',
  '7.0(3)I1(1a)',
  '7.0(3)I1(1b)',
  '7.0(3)I1(2)',
  '7.0(3)I1(3)',
  '7.0(3)I1(3a)',
  '7.0(3)I1(3b)',
  '7.0(3)I2(2a)',
  '7.0(3)I2(2b)',
  '7.0(3)I2(2c)',
  '7.0(3)I2(2d)',
  '7.0(3)I2(2e)',
  '7.0(3)I2(3)',
  '7.0(3)I2(4)',
  '7.0(3)I2(5)',
  '7.0(3)I2(1)',
  '7.0(3)I3(1)',
  '7.0(3)I4(1)',
  '7.0(3)I4(2)',
  '7.0(3)I4(3)',
  '7.0(3)I4(4)',
  '7.0(3)I4(5)',
  '7.0(3)I4(6)',
  '7.0(3)I4(7)',
  '7.0(3)I4(8)',
  '7.0(3)I4(8a)',
  '7.0(3)I4(8b)',
  '7.0(3)I4(8z)',
  '7.0(3)I5(1)',
  '7.0(3)I5(2)',
  '7.0(3)I6(1)',
  '7.0(3)I6(2)',
  '7.0(3)I7(1)',
  '7.0(3)I7(2)',
  '7.0(3)I7(3)',
  '7.0(3)IX1(2)',
  '7.0(3)IX1(2a)',
  '8.1(1)',
  '8.1(2)',
  '8.1(2a)',
  '8.2(1)',
  '8.2(2)'
);

if ('Nexus' >< product_info.device)
{
  if (product_info.model =~ '^(3|9)')
    cbi = 'CSCvj59431, CSCvk52941, CSCvk52940';
  else if (product_info.model =~ '^7[07][0-9][0-9]')
    cbi = 'CSCvj59446';
}

if (empty_or_null(cbi))
  audit(AUDIT_HOST_NOT, 'affected');

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , cbi
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
