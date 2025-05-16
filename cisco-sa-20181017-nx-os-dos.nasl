#TRUSTED 7f2a9b97cc148314e9236a362e9874be1b0cdf2a5e3916ce29c580885f553fd9cb275c860ff3119254d5898db40a0091b8091579fbeb6fbf4e046c5d31c589b8f67435f0f9fb64a0aa8a884a9c6247701eab431c9081967c9437910c09db3bd34e5404ff5d62f9d734c8293068d833ce0285524e13f663c703cd2460908244e752a0506075c91eedc68af414c2817553e7d528d6027673c4f718f212a81af31bd4180b3d99e4990e2e8399c2d005462f269240e02ac102f70a058562a7e075350592415bd1847ef1c71d34ffce93bb83e66708692c94e4e7018519ae9785c7aafcc3963c39269c89056ec5b3a34198d20132acb802a5f7475d44d091e85a89591a145e84ef05a822396bf1da522d0f03e03a5c72e9e26628d35a4a4c74573f6879eb09155a856cbc6a81ba46531c3dc7309471b9a484119c1fe39d7713e668e7c100cfbb881b9cc81c6e7ab2201ea45877f218651801a1ac47aadca30a087f687138f184629a7f5de5ce3230ff6fa9a6a7aeabd4df491197884f2087dcf86017ac871b9f684b789e289f2cfa7a120dad17a665916a9df16f10d17335cb42071fb38556b4ddd33dcfd1841641185deaff0c29768c37e01d0445fcb7feaf55e01122b7959565ff45a4e01977055c6e3bc9e50b10fbf60996ced2d79dac521b12a6ff81147693953b838109a15ae51aeaace250bca2a6f140e49c4c22148fc8822b
#TRUST-RSA-SHA256 65cddae76d0fd2a5288cee739010567d1115242b6a8081ba7e61d97b82aec011a93d469534eeab57ee1687463fee28a780e8119e42a2945e1f95bfc7bed5b2fee39f5cedff5b5d2007b63e926b773e2010a91e54e2b437103a1fbaecfc2d1f7359b44a1eed3e6d0c3c54982f6f28149e1c2a3f459f64b9765dfdd13800a82250ce3fab72089341565e5e7edc9e198d7bda0b0b9731c9a733a4eeddf20cc42ca8edefa09f4e0019e0f3700805871eb8f6e07d341778d7c82bf5cb4b6469e639805134a7304f57db6829f0881960f039e6b73ceed2f1ac6f4035c15aad06624f9586c3a779f1ebe192df08369e1b94eb6c7bcd310fdf50708d409088f27be9e6c70c3d8b04866962bc3c9b6a329154b0187849b5d1ecab8581cd8060509ebdb926cdbf4d1dd9fe5b870ee53bf5d2f6872cb71273d70942aa270dab01b62ad6ccfdf6783de90687aee85e646c901d1b11fd470099021f0c56650830d96d48e1e7a4a35d94efdad141e247b1dd65acfb01629cafb56978147b32b6f80d1c0d5371faa53310b5ad13ed5c9cca4273bd72335074d084b59ac0391e010d2979ec39729a7741ac7ceef8989a0d652e5029f1e5f51bea7e5a6bab894b50168e34eb41a8ba104c89cd5272cc717dddb6236b33a7b7f8f8310f91454552a69161b10e94dc33f748e10e5103a6429ae182c76e9436c8a94c848c3fa1ec2924cc97b09dc9b867
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(134947);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/21");

  script_cve_id("CVE-2018-0395");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuc98542");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvj94174");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvj96148");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20181017-fxnx-os-dos");

  script_name(english:"Cisco NX-OS Software Link Layer Discovery Protocol Denial of Service Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A denial of service (DoS) vulnerability exists in Cisco NX-OS Software due to improper input validation of
certain type, length, value (TLV) fields of the LLDP frame header. An unauthenticated, local attacker can exploit this
issue, by sending a crafted LLDP packet to an interface on the targeted device, to cause the system to reload.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20181017-fxnx-os-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3775192a");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuc98542");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj94174");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj96148");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCuc98542, CSCvj94174, CSCvj96148");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0395");
  script_set_attribute(attribute:"cvss3_score_rationale", value:"Scoring adjustsed to align with CVSS 3.1 attack complexity guidance.");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/27");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Device", "Host/Cisco/NX-OS/Model", "Settings/ParanoidReport");

  exit(0);
}


include('ccf.inc');
include('cisco_workarounds.inc');

product_info = cisco::get_product_info(name:"Cisco NX-OS Software");

if ('Nexus' >< product_info['device'])
{
  # check if 2000 , 5500, 5600, or 6000 series
  if (preg(pattern:"^20[0-9]{2}$", string:product_info['model']) ||
      preg(pattern:"^5[5-6][0-9]{2}$", string:product_info['model']) ||
      preg(pattern:"^6[0-9]{3}$", string:product_info['model']))
    {
    bid = 'CSCuc98542';
    vuln_ranges = [
    {'min_ver' : '5.0', 'fix_ver' : '7.0(0)N1(1)'}
    ];
  }
  # check if 3000 series
  else if (preg(pattern:"^30[0-9]{2}$", string:product_info['model']))
  {
    bid = 'CSCuc98542';
    vuln_ranges = [
    {'min_ver' : '5.0(3)', 'fix_ver' : '6.0(2)U1(2)'}
    ];
  }
  # check if 3500 series
  else if (preg(pattern:"^35[0-9]{2}$", string:product_info['model']))
  {
    bid = 'CSCuc98542';
    vuln_ranges = [
    {'min_ver' : '5.0(3)', 'fix_ver' : '6.0(2)A1(1b)'}
    ];
  }
  # check if 7000 or 7700 series
  else if (preg(pattern:"^7(0|7)[0-9]{2}$", string:product_info['model']))
  {
    bid = 'CSCuc98542';
    vuln_ranges = [
    {'min_ver' : '5.2', 'fix_ver' : '5.2(9)'},
    {'min_ver' : '6.1', 'fix_ver' : '6.1(3)'}
    ];
  }
  # check if 9000 series
  else if (preg(pattern:"^90[0-9]{2}$", string:product_info['model']))
  {
    bid = 'CSCvj94174';
    vuln_ranges = [
    {'min_ver' : '0.0', 'fix_ver' : '13.2(2l)'}
    ];
  }
}
else if ('MDS' >< product_info['device'])
{
  # check if 9000 series
  if (preg(pattern:"^90[0-9]{2}$", string:product_info['model']))
  {
    bid = 'CSCuc98542';
    vuln_ranges = [
    {'min_ver' : '5.2', 'fix_ver' : '6.2(1)'}
    ];
  }
}
else if ('UCS' >< product_info['device'])
{
  # check if 6100, 6200, and 6300 Series
  if (preg(pattern:"^6[1-3][0-9]{2}$", string:product_info['model']))
    {
    bid = 'CSCvj96148';
    vuln_ranges = [
    {'min_ver' : '0.0', 'fix_ver' : '2.2(8l)'},
    {'min_ver' : '3.1', 'fix_ver' : '3.1(3j)'},
    {'min_ver' : '3.2', 'fix_ver' : '3.2(3g)'},
    {'min_ver' : '4.0', 'fix_ver' : '4.0(1a)'}
    ];
  }
}
if (bid == '')
{
  audit(AUDIT_HOST_NOT, 'a vulnerable model');
}


if (report_paranoia < 2) audit(AUDIT_PARANOID);

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = [];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_NOTE,
  'bug_id'   , bid,
  'version'  , product_info['version']
);

cisco::check_and_report(product_info:product_info,
  workarounds       : workarounds,
  workaround_params : workaround_params,
  reporting         : reporting,
  vuln_ranges       : vuln_ranges
);
