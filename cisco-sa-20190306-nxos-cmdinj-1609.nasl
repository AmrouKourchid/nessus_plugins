#TRUSTED 3bd8906305d38413d9f2bf067120bb67ee9c9fd01b320db3745b848575efa833683f4f5cc60b4a890837a8999621d2d483a8fdbb2638fa50dea0608ced502a2ce3a3700c0e319120bcf74b6bb917f72d65047577e8a5a3c3b8c5e56de997c5310567f1adc986b054be36faaa1b836e869bd15d23973e159412a113351b793288010410bbab939f42c605e813c67e83debd8e4dcc2c9b88f32007505b55e7eb0bd109078f78be98296a00089a6c0bd6e6ab414a190591cfdb544d8671ecb614726dc2244941c8ce45663f437cd513e32429f8a74e4404d6bc03cf86be9125d03bbf539780fb5afece7044925cf22014739b5ed6f095ad071dd334bf138fb451b8fc0017d850108a71bce975a976b8ef1b0c4417199d19cc121fb95fde2ab99a8b466d918ec7ddf0721370205a0ea9ce5c5e20ff22ed9e3e5ae88dccc313b8816f004b36b5b3b991d1171fef9adae5b9ecd6220b141deea933eb2bf9a9755d270a07d938a13eaacdd205b86e6cc696879f6247189da46b751c3d51ad7c6851ebe028eeb31ff8801c9b384ce187a1646e59f8199439d2f45e514b40138ae350bd44615a1757050f9e15988edf455b695876462a9ef62abacfcfb1c34d4f8a35c16e31b54f84a915b15a5a91f59a8d135797c029b339b2d4d97b0feed614d3f434ec829015ecfdab2fa2babacb4669b8a667ba00bcdc5c4c0e1efaf4ea9ace14ab9d
#TRUST-RSA-SHA256 5fc94c18d2ad6a7981f5a3926e85fcf973c299d7c5e4f37f56a0915bd995707449baceca9f638fef6327ae19dff3062a92dfb9dc66e6f00949cd7601e19c1e86de8d23524ce4d7d742e1ba27c92b284001561a1f0b057e3ffa27ca7b22f69811773bec50f5885422d9e90c27c949f86d511d8991d4d86aa2f381d23081a9349db5a3e05bec70350ff93a2b54352e7a9e354cc5b00c03c2141c7d164323b7e8c2bcace4e06f82d3d19952d2cc55c9b7da07fe284d95a0c1a99b522ad34ad4ef97e7a70d63d192a7b0d3342dcb8e9ef7d7974f0e653583bfa521fb8ca30869d3746a3f4be1507246c6525c18c2775734675e87510adf3ff6f631cf0b13047cbb6f0314666172a46638138590c803494712e6b448829a0f53964e08ff4019e4bf947acab55cf4533bc04eb261ff7bbf6538171e58d01c509bd408796e1746706336dbb1c68b53be279e2724bddecfbbe89b4a4b5b2fd9915d2377f4d802cefd39b4fbc89be21d0a1020f591e1e24ed2133d322a41f0ef594b8a22489683e001656f80b23ae7cf416140bb36888e6ef52b8c22f13d67e7def5362cbfcf7adcc7835ba0b7d56477815ad84ba8805c721934e81a242e21320c2b92b8ad099a17e345fb0982acc2414da0ff7e71842e4e1d7902d8dd597db0383693531cfd40c09a8ba58e37f9c2c18e6b1fdcdaa43f65fcbe3b71ddf99a760da4e29e5db8349aeacb24
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(132414);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/03");

  script_cve_id("CVE-2019-1609");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvk51387");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190306-nxos-cmdinj-1609");

  script_name(english:"Cisco NX-OS Software CLI Command Injection Vulnerability (Cisco-Sa-20190306-Nxos-Cmdinj-1609)");
  script_summary(english:"Checks the version of Cisco NX-OS Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco NX-OS Software is
affected by following vulnerability

  - A vulnerability in the CLI of Cisco NX-OS Software could
    allow an authenticated, local attacker to execute
    arbitrary commands on the underlying operating system of
    an affected device.The vulnerability is due to
    insufficient validation of arguments passed to certain
    CLI commands. An attacker could exploit this
    vulnerability by including malicious input as the
    argument of an affected command. A successful exploit
    could allow the attacker to execute arbitrary commands
    on the underlying operating system with elevated
    privileges. An attacker would need valid administrator
    credentials to exploit this vulnerability.
    (CVE-2019-1609)

Please see the included Cisco BIDs and Cisco Security Advisory for
more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190306-nxos-cmdinj-1609
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6d2b8c46");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-70757");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvk51387");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvk51387");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1609");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(77);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/27");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Model", "Host/Cisco/NX-OS/Device");

  exit(0);
}

include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");

product_info = cisco::get_product_info(name:"Cisco NX-OS Software");

cbi = '';

switch (product_info)
{
  case product_info.device == 'MDS':
    if (product_info.model =~ "90[0-9][0-9]") cbi = "CSCvk51388";
    else audit(AUDIT_HOST_NOT, 'affected');
  break;
  case product_info.device != 'Nexus':
    audit(AUDIT_HOST_NOT, 'affected');
  break;
  case product_info.model =~ '^(3[05]|90)[0-9][0-9]':
	cbi = "CSCvj63253";
  break;
  case product_info.model =~ '^(70|77)[0-9][0-9]': #7000 and 7700 series
	cbi = "CSCvk51388";
  break;
  case product_info.model =~ '^(36|95)[0-9][0-9]': #9500 series
	cbi = "CSCvk51387";
  break;
  default:
    audit(AUDIT_HOST_NOT, 'affected');
}

version_list=make_list(
  '8.3(1)',
  '8.2(2)',
  '8.2(1)',
  '8.1(2a)',
  '8.1(2)',
  '8.1(1a)',
  '8.1(1)',
  '8.0(1)',
  '7.3(2)D1(3a)',
  '7.3(2)D1(3)',
  '7.3(2)D1(2)',
  '7.3(2)D1(1)',
  '7.3(1)DY(1)',
  '7.3(1)D1(1)',
  '7.3(0)DY(1)',
  '7.3(0)DX(1)',
  '7.3(0)D1(1)',
  '7.2(2)D1(2)',
  '7.2(2)D1(1)',
  '7.2(1)D1(1)',
  '7.2(0)D1(1)',
  '7.0(3)IX1(2a)',
  '7.0(3)IX1(2)',
  '7.0(3)I7(5a)',
  '7.0(3)I7(5)',
  '7.0(3)I7(4)',
  '7.0(3)I7(3)',
  '7.0(3)I7(2)',
  '7.0(3)I7(1)',
  '7.0(3)I6(2)',
  '7.0(3)I6(1)',
  '7.0(3)I5(2)',
  '7.0(3)I5(1)',
  '7.0(3)I4(8z)',
  '7.0(3)I4(8b)',
  '7.0(3)I4(8a)',
  '7.0(3)I4(8)',
  '7.0(3)I4(7)',
  '7.0(3)I4(6)',
  '7.0(3)I4(5)',
  '7.0(3)I4(4)',
  '7.0(3)I4(3)',
  '7.0(3)I4(2)',
  '7.0(3)I4(1)',
  '7.0(3)I3(1)',
  '7.0(3)I2(5)',
  '7.0(3)I2(4)',
  '7.0(3)I2(3)',
  '7.0(3)I2(2e)',
  '7.0(3)I2(2d)',
  '7.0(3)I2(2c)',
  '7.0(3)I2(2b)',
  '7.0(3)I2(2a)',
  '7.0(3)I2(1)',
  '7.0(3)I1(3b)',
  '7.0(3)I1(3a)',
  '7.0(3)I1(3)',
  '7.0(3)I1(2)',
  '7.0(3)I1(1b)',
  '7.0(3)I1(1a)',
  '7.0(3)I1(1)',
  '7.0(3)F3(4)',
  '7.0(3)F3(3c)',
  '7.0(3)F3(3a)',
  '7.0(3)F3(3)',
  '7.0(3)F3(2)',
  '7.0(3)F3(1)',
  '7.0(3)F2(2)',
  '7.0(3)F2(1)',
  '7.0(3)F1(1)',
  '7.0(2)I2(2c)',
  '6.2(9c)',
  '6.2(9b)',
  '6.2(9a)',
  '6.2(9)',
  '6.2(8b)',
  '6.2(8a)',
  '6.2(8)',
  '6.2(7)',
  '6.2(6b)',
  '6.2(6a)',
  '6.2(6)',
  '6.2(5b)',
  '6.2(5a)',
  '6.2(5)',
  '6.2(3)',
  '6.2(2a)',
  '6.2(25)',
  '6.2(23)',
  '6.2(21)',
  '6.2(20a)',
  '6.2(20)',
  '6.2(2)',
  '6.2(19)',
  '6.2(18)',
  '6.2(17)',
  '6.2(16)',
  '6.2(15)',
  '6.2(14)',
  '6.2(13b)',
  '6.2(13a)',
  '6.2(13)',
  '6.2(12)',
  '6.2(11e)',
  '6.2(11d)',
  '6.2(11c)',
  '6.2(11b)',
  '6.2(11)',
  '6.2(10)',
  '6.2(1)',
  '6.1(5a)',
  '6.1(5)',
  '6.1(4a)',
  '6.1(4)',
  '6.1(3)',
  '6.1(2)I3(5b)',
  '6.1(2)I3(5a)',
  '6.1(2)I3(5)',
  '6.1(2)I3(4e)',
  '6.1(2)I3(4d)',
  '6.1(2)I3(4c)',
  '6.1(2)I3(4b)',
  '6.1(2)I3(4a)',
  '6.1(2)I3(4)',
  '6.1(2)I3(3a)',
  '6.1(2)I3(3)',
  '6.1(2)I3(2)',
  '6.1(2)I3(1)',
  '6.1(2)I2(3)',
  '6.1(2)I2(2b)',
  '6.1(2)I2(2a)',
  '6.1(2)I2(2)',
  '6.1(2)I2(1)',
  '6.1(2)I1(3)',
  '6.1(2)I1(1)',
  '6.1(2)',
  '6.1(1)',
  '6.0(4)',
  '6.0(3)',
  '6.0(2)U6(9)',
  '6.0(2)U6(8)',
  '6.0(2)U6(7)',
  '6.0(2)U6(6)',
  '6.0(2)U6(5c)',
  '6.0(2)U6(5b)',
  '6.0(2)U6(5a)',
  '6.0(2)U6(5)',
  '6.0(2)U6(4a)',
  '6.0(2)U6(4)',
  '6.0(2)U6(3a)',
  '6.0(2)U6(3)',
  '6.0(2)U6(2a)',
  '6.0(2)U6(2)',
  '6.0(2)U6(1a)',
  '6.0(2)U6(10)',
  '6.0(2)U6(1)',
  '6.0(2)U5(4)',
  '6.0(2)U5(3)',
  '6.0(2)U5(2)',
  '6.0(2)U5(1)',
  '6.0(2)U4(4)',
  '6.0(2)U4(3)',
  '6.0(2)U4(2)',
  '6.0(2)U4(1)',
  '6.0(2)U3(9)',
  '6.0(2)U3(8)',
  '6.0(2)U3(7)',
  '6.0(2)U3(6)',
  '6.0(2)U3(5)',
  '6.0(2)U3(4)',
  '6.0(2)U3(3)',
  '6.0(2)U3(2)',
  '6.0(2)U3(1)',
  '6.0(2)U2(6)',
  '6.0(2)U2(5)',
  '6.0(2)U2(4)',
  '6.0(2)U2(3)',
  '6.0(2)U2(2)',
  '6.0(2)U2(1)',
  '6.0(2)U1(4)',
  '6.0(2)U1(3)',
  '6.0(2)U1(2)',
  '6.0(2)U1(1a)',
  '6.0(2)U1(1)',
  '6.0(2)',
  '6.0(1)',
  '5.2(9a)',
  '5.2(9)',
  '5.2(8i)',
  '5.2(8h)',
  '5.2(8g)',
  '5.2(8f)',
  '5.2(8e)',
  '5.2(8d)',
  '5.2(8c)',
  '5.2(8b)',
  '5.2(8a)',
  '5.2(8)',
  '5.2(7)',
  '5.2(6b)',
  '5.2(6a)',
  '5.2(6)',
  '5.2(5)',
  '5.2(4)',
  '5.2(3a)',
  '5.2(3)',
  '5.2(2s)',
  '5.2(2d)',
  '5.2(2a)',
  '5.2(2)',
  '5.2(1)',
  '5.1(6)',
  '5.1(5)',
  '5.1(4)',
  '5.1(3)',
  '5.1(1a)',
  '5.1(1)',
  '5.0(8a)',
  '5.0(8)',
  '5.0(7)',
  '5.0(5)',
  '5.0(4d)',
  '5.0(4c)',
  '5.0(4b)',
  '5.0(4)',
  '5.0(3)U5(1j)',
  '5.0(3)U5(1i)',
  '5.0(3)U5(1h)',
  '5.0(3)U5(1g)',
  '5.0(3)U5(1f)',
  '5.0(3)U5(1e)',
  '5.0(3)U5(1d)',
  '5.0(3)U5(1c)',
  '5.0(3)U5(1b)',
  '5.0(3)U5(1a)',
  '5.0(3)U5(1)',
  '5.0(3)U4(1)',
  '5.0(3)U3(2b)',
  '5.0(3)U3(2a)',
  '5.0(3)U3(2)',
  '5.0(3)U3(1)',
  '5.0(3)U2(2d)',
  '5.0(3)U2(2c)',
  '5.0(3)U2(2b)',
  '5.0(3)U2(2a)',
  '5.0(3)U2(2)',
  '5.0(3)U2(1)',
  '5.0(3)U1(2a)',
  '5.0(3)U1(2)',
  '5.0(3)U1(1d)',
  '5.0(3)U1(1c)',
  '5.0(3)U1(1b)',
  '5.0(3)U1(1a)',
  '5.0(3)U1(1)',
  '5.0(3)',
  '5.0(2a)',
  '5.0(2)',
  '5.0(1b)',
  '5.0(1a)',
  '4.2(8)',
  '4.2(6)',
  '4.2(4)',
  '4.2(3)',
  '4.2(2a)',
  '4.1(5)',
  '4.1(4)',
  '4.1(3)',
  '4.1(2)'
);

reporting = make_array(
'port'     , 0,
'severity' , SECURITY_HOLE,
'version'  , product_info['version'],
'bug_id'   , cbi,
'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list,
  switch_only:TRUE
);
