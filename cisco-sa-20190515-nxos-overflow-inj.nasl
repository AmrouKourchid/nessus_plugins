#TRUSTED 50e5f44a6b40b85a07dded04e15875b64aa85a5eee2a094a44f7107296ac594651e946f56f259cd624fae18f70e09dc4df15cf8cf54b7a1690ecc35e86fc9d8e08fdeae6328df7f52574b409ed83cddb794f1cb3a7cf0bcd8ff77727c41ea8e79a4608a1cf18760ea4688bfd8b621089098d5992582b3ad011acbbcb6c8cb2a20c1675c218c3c589b9bf70210c36cd47162fbbe50307d0935b04df6e255c52cbbc9b2deb299a3a8dcbf99391abc8fb912aeadd43264230048221ab39af1f9eb5045e035f551eae1aa190f3ef90d37e58eba1ba6db3449417e138cc016c283ae1174667b052bdbcb10b67496e0a87b93a09ca79d8b210e877ce63db51db48bf35cdf16fa0c74b5346456bcec02b9119a14261ac10829a8857dd78cb28a7e26d17f4e87a23127e684d2b3902777c43cccb2f4b46929f1b91250c4a463a53f78a27dd8df84f9e831a850309d7612ca1f9360c263644f84d8f1dcbe6ab772e1ca36c2053b0c597a52e4f71fa5c45cf50235a6b48c1da919345f404567a54fda9363c95d4f1ce0e6d039abb79631b82e12b70d692cd6bc136b8adfeb2b5eacdb4565f092716b77888a7dcf4f0075538a18b18eecbbd1c4e99b89a9974a8929b6f142c3aa47f5dab525d712947adc467c359f645e4ca1d3071838f08b2bc379fbad8b26e54a760eb44adf2f56dd427f89d8ce2128724b15c4ca8b79743af5fd7c3fbc1
#TRUST-RSA-SHA256 23b79224ba17bb819583ae663ede8ce3971d88d2115a5198c7d1255c1c1846c483dd144e939e3a5e855c54fdf7c312eb40bc61b2dce8764894420adb7304d745b13b782305c6015ce3d271ead71891aeb578d84232966a96c6b9fb559a74db348c85a0aab8c14cec3ef54a80aa6195eb837bde175ee2e5b765288dbb7a329abd96b6d6a70cd6a7b4bf04d31f249ce7d61d08348562b48af22c56c6bd6d8061f60f506faaf264bc2b897a3a30d7990d0e9d18713532d1fe668ad567953d8438fa7888975a8e7909380433139463cc771da3424f40a2a795e14702770304d37be0b39f16f16a5f7aa3e9184658c5d88f9e039d154252e1ff6a470ed0b0fb14c5f895a345c3e346165324d180b706d786a24da0da11b7bc2d9eb084f3c67f444c620121862d6ee6d0991eac9ef4ebac1201d9224ebffa01ee048f3279c6a45877f33cab9de5a59f49da341305a6b3d2ce50ec15bc2722ed3395e2bba068e97f5aec25590af310b23c20a84d1758e036b569fa2a78676a352ec7f8777d7333e8132bb18c15f96cbfa26327f95be8d0b2fcca10913f44d05bd522370b9cf1c530cb9b64e6815312e2d190206fb4e65ecc797965ea5c867070ef2c5956357481dd304c6d2d3fdd44e263b4f799c625b1ea39d67d751f3270aa12546fbdbb48af65d730510c0c9907e18856ebc6954cc674b7606acaa7f1eb10bfd02552104a185c57f9
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(126342);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/14");

  script_cve_id("CVE-2019-1767", "CVE-2019-1768");
  script_bugtraq_id(108386);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvh76132");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvh76129");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvj00497");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvj10162");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190515-nxos-overflow-inj");
  script_xref(name:"IAVA", value:"2019-A-0173");

  script_name(english:"Cisco NX-OS Software Buffer Overflow and Command Injection Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco NX-OS Software is
affected by a vulnerability in the implementation of a specific CLI
command for Cisco NX-OS Software could allow an authenticated, local
attacker with administrator credentials to cause a buffer overflow
condition  or perform command injection. This could allow the
attacker to execute arbitrary commands with elevated privileges
on the underlying operating system of an affected device. The
vulnerability is due to insufficient validation of arguments
passed to a certain CLI command. An attacker could exploit this
vulnerability by including malicious input as the argument of
the affected CLI command. A successful exploit could allow
the attacker to execute arbitrary commands on the underlying
operating system with root privileges. An attacker would need
valid administrator credentials to exploit this vulnerability.
(CVE-2019-1767) (CVE-2019-1768)

Please see the included Cisco BIDs and Cisco Security Advisory for
more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190515-nxos-overflow-inj
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d4f90baf");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvh76132");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvh76129");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj00497");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj10162");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs
CSCvh76132, CSCvh76129, CSCvj00497, CSCvj10162");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1768");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(77, 119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/28");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Model", "Host/Cisco/NX-OS/Device");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco NX-OS Software');
bugIDs = NULL;

if ('Nexus' >< product_info.device)
{
  if (product_info.model =~ '^3[05][0-9][0-9]' || product_info.model =~ '^90[0-9][0-9]') bugIDs = 'CSCvh76132, CSCvh76129';
  else if (product_info.model =~ '^36[0-9][0-9]' || product_info.model =~ '^95[0-9][0-9]') bugIDs = 'CSCvj00497, CSCvj10162';
}

if (isnull(bugIDs)) audit(AUDIT_HOST_NOT, 'affected');

version_list=make_list(
  '7.0',
  '7.0(0)N1',
  '7.0(0)N1(1)',
  '7.0(1)N1',
  '7.0(1)N1(1)',
  '7.0(1)N1(3)',
  '7.0(2)I2',
  '7.0(2)I2(2c)',
  '7.0(2)N1',
  '7.0(2)N1(1)',
  '7.0(2)N1(1a)',
  '7.0(3)',
  '7.0(3)F1',
  '7.0(3)F1(1)',
  '7.0(3)F2',
  '7.0(3)F2(1)',
  '7.0(3)F2(2)',
  '7.0(3)F3',
  '7.0(3)F3(1)',
  '7.0(3)F3(2)',
  '7.0(3)F3(3)',
  '7.0(3)F3(3a)',
  '7.0(3)F3(3b)',
  '7.0(3)F3(3c)',
  '7.0(3)F3(4)',
  '7.0(3)I1',
  '7.0(3)I1(1)',
  '7.0(3)I1(1a)',
  '7.0(3)I1(1b)',
  '7.0(3)I1(2)',
  '7.0(3)I1(3)',
  '7.0(3)I1(3a)',
  '7.0(3)I1(3b)',
  '7.0(3)I2',
  '7.0(3)I2(1)',
  '7.0(3)I2(1a)',
  '7.0(3)I2(2)',
  '7.0(3)I2(2a)',
  '7.0(3)I2(2b)',
  '7.0(3)I2(2c)',
  '7.0(3)I2(2d)',
  '7.0(3)I2(2e)',
  '7.0(3)I2(3)',
  '7.0(3)I2(4)',
  '7.0(3)I2(5)',
  '7.0(3)I3',
  '7.0(3)I3(1)',
  '7.0(3)I4',
  '7.0(3)I4(1)',
  '7.0(3)I4(2)',
  '7.0(3)I4(3)',
  '7.0(3)I4(4)',
  '7.0(3)I4(5)',
  '7.0(3)I4(6)',
  '7.0(3)I4(7)',
  '7.0(3)I5',
  '7.0(3)I5(1)',
  '7.0(3)I5(2)',
  '7.0(3)I6',
  '7.0(3)I6(1)',
  '7.0(3)I6(2)',
  '7.0(3)I7',
  '7.0(3)I7(1)',
  '7.0(3)I7(2)'
);

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();


reporting = make_array(
'port'     , 0,
'severity' , SECURITY_HOLE,
'version'  , product_info['version'],
'bug_id'   , bugIDs
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
