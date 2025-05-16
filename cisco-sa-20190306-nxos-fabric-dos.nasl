#TRUSTED 66c7d83450dd04b1275a18e358ddd6aef30e9810f317355e502722940ecf79609a3306fd45f55f704dc0e76bf978ef2cec5fe5b9d47aae2899b74758e00e05c6fe236a63bcfe323e1c496047ab66dcdd15e8f7c2e5eb4b71da33f55ca3a8a366c8b9577ab87c7de0362c5d7f6aab221d40471b9dd0a859985ca495fb6c322f86dbeda524d941612711843d90a416094d0483a14a7bee1be56b40b5a2cd108e0e589fe7be6fdf6d33b50564942fac909126d82a20cc4bf88363b4620d3a9b76c50f45c7bf67b9c20db2f6f4e28d462b2d7b0f1da9cc7e812ad4c035f7b0f1ec85faab2f91253b447930dc9a28769c6846dedb65ab333064a2823ed45bcd889dbbc74e612d15eb7aa6e63e4b5e1ceeb455d0d04f727166c8ca7bd26d12a0597b8d11b6a96be7e9e933c8a9e5fcb3c3e93531b7b830d223b97d66bb35ec5cfed16821c3fbb35005d081428653cb3681cadde06f174e8e0a66f1363e826d156a3b8bc9de2a4f788773da44d0fb701c6ed96de0073ad4e092ff1b8bb5abf81bf48ffefca887f0535b97276b2bc44541cfc07ed5438cd632c962e72f48c0d9c9b02ac9a2d838c10a21a8c127df27a055eb0d13d4eb9db4e11620c9c488d6240f2c25b2a25abc91a8d79650244dee1ca4a9cd44386b68dea885d638f5fcc99f17490aafeff553d5a883b41f8c1580514955656eb10625911a65e2a02b91870d678e03a2
#TRUST-RSA-SHA256 767e8da45ac33a1422e8e17d099d8315e691b1982ddf92b201e44f30d40193a3c3b456b11b78c1659a342908ba3af7bd76221bea619074abd75b88ce5ac5a88cb553b45714899c5dc86017c758ef0948e8ba43d4e9a0de4544a9bb3f800ae39572972815056395abdfe60598bc792d241097f27c6ad5857b9f1e594f395fc30c2739ca7aafe1c80309375d8b5084474073ce4e053a1170aa8f24c974a0028d13641f3377a8528e81d588a1ebd0ec98f463115bc7622819ec8cd844f030e35c621f86e3fc8bd5147df00228d4d9da4c6752be2ede771962e5eaaaf6a4f503c86dd9cca3e95f973ebcf302952e246c4a761ad89112863e0c2fbf88ff49ffb5650b4d2cdc323b0a77a26ca52a9ae4a31ea57ada89afbfe6da3f3b4ef770ec7915d152dff291fa2f1262d9998603773519c69c3802af71bd94e47222673867aff94ac22fd6f516c49a2bdb72dedcae203e963cbb2298f0f9454e172ff08b05d8ca469f08cefb48ff56376d32b39aaba96835f7f3332d300d9ce02d7c4d994b20228218075624795f2b6a5f3c13eddf4781ba92977e75ce9d8799a885d2d479bab571e647016985e050c52a35937f07e50c8a20f253288c2b599df71318cd549141005e465d497c6dc0a57a6695279f4620b6007df8956b9668cf401d87ef057d7aaa72214ed00147ca82831b77680da244a79819431d7bab1e94f796261dbf2d19bd
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(126477);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/10");

  script_cve_id("CVE-2019-1616");
  script_bugtraq_id(107395);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvh99066");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvj10176");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvj10178");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvj10181");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvj10183");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190306-nxos-fabric-dos");

  script_name(english:"Cisco NX-OS Software Cisco Fabric Services Denial of Service Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote Cisco device is affected by denial of service (DoS)
    vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco NX-OS Software
is affected by a denial of service (DoS) vulnerability. It exists in Cisco fabric services due to insufficient
validation of Cisco fabric service packets. An unauthenticated, remote attacker can exploit this issue, via sending a
crafted Cisco fabric services packet to an affected device. A successful exploit could allow the attacker to cause a
buffer overflow, resulting in a DoS condition on the device.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190306-nxos-fabric-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c2417bde");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvh99066");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj10176");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj10178");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj10181");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj10183");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s)
CSCvh99066 / CSCvj10176 / CSCvj10178 / CSCvj10181 / CSCvj10183.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1616");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/04");

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
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco NX-OS Software');

cbi = '';

if ('MDS' >< product_info.device && product_info.model =~ '^90[0-9][0-9]')
  cbi = 'CSCvj10178';
else if ('UCS'>< product_info.device && product_info.model =~ '^6[2-4][0-9][0-9]')
  cbi = 'CSCvj10183';
else if ('Nexus' >< product_info.device)
{
  if (product_info.model =~ '^3[056][0-9][0-9]')
    cbi = 'CSCvh99066, CSCvj10181, CSCvj10176';
  else if (product_info.model =~ '^7[07][0-9][0-9]')
    cbi = 'CSCvj10178';
  else if (product_info.model =~ '^9[05][0-9][0-9]')
    cbi = 'CSCvh99066, CSCvj10176';
 }

if (empty_or_null(cbi))
  audit(AUDIT_HOST_NOT, 'affected');

version_list=make_list(
  '5.0(1a)',
  '5.0(1b)',
  '5.0(3)A1(1)',
  '5.0(3)A1(2)',
  '5.0(3)A1(2a)',
  '5.0(3)U1(1)',
  '5.0(3)U1(1a)',
  '5.0(3)U1(1b)',
  '5.0(3)U1(1c)',
  '5.0(3)U1(1d)',
  '5.0(3)U1(2)',
  '5.0(3)U1(2a)',
  '5.0(3)U2(1)',
  '5.0(3)U2(2)',
  '5.0(3)U2(2a)',
  '5.0(3)U2(2b)',
  '5.0(3)U2(2c)',
  '5.0(3)U2(2d)',
  '5.0(3)U3(1)',
  '5.0(3)U3(2)',
  '5.0(3)U3(2a)',
  '5.0(3)U3(2b)',
  '5.0(3)U4(1)',
  '5.0(3)U5(1)',
  '5.0(3)U5(1a)',
  '5.0(3)U5(1b)',
  '5.0(3)U5(1c)',
  '5.0(3)U5(1d)',
  '5.0(3)U5(1e)',
  '5.0(3)U5(1f)',
  '5.0(3)U5(1g)',
  '5.0(3)U5(1h)',
  '5.0(3)U5(1i)',
  '5.0(3)U5(1j)',
  '5.0(4)',
  '5.0(4b)',
  '5.0(4c)',
  '5.0(4d)',
  '5.0(7)',
  '5.0(8)',
  '5.0(8a)',
  '5.2(1)',
  '5.2(2)',
  '5.2(2a)',
  '5.2(2d)',
  '5.2(2s)',
  '5.2(6)',
  '5.2(6a)',
  '5.2(6b)',
  '5.2(8)',
  '5.2(8a)',
  '5.2(8b)',
  '5.2(8c)',
  '5.2(8d)',
  '5.2(8e)',
  '5.2(8f)',
  '5.2(8g)',
  '5.2(8h)',
  '5.2(8i)',
  '6.0(2)A1(1)',
  '6.0(2)A1(1a)',
  '6.0(2)A1(1b)',
  '6.0(2)A1(1c)',
  '6.0(2)A1(1d)',
  '6.0(2)A1(1e)',
  '6.0(2)A1(1f)',
  '6.0(2)A1(2d)',
  '6.0(2)A3(1)',
  '6.0(2)A3(2)',
  '6.0(2)A3(4)',
  '6.0(2)A4(1)',
  '6.0(2)A4(2)',
  '6.0(2)A4(3)',
  '6.0(2)A4(4)',
  '6.0(2)A4(5)',
  '6.0(2)A4(6)',
  '6.0(2)A6(1)',
  '6.0(2)A6(1a)',
  '6.0(2)A6(2)',
  '6.0(2)A6(2a)',
  '6.0(2)A6(3)',
  '6.0(2)A6(3a)',
  '6.0(2)A6(4)',
  '6.0(2)A6(4a)',
  '6.0(2)A6(5)',
  '6.0(2)A6(5a)',
  '6.0(2)A6(5b)',
  '6.0(2)A6(6)',
  '6.0(2)A6(7)',
  '6.0(2)A6(8)',
  '6.0(2)A7(1)',
  '6.0(2)A7(1a)',
  '6.0(2)A7(2)',
  '6.0(2)A7(2a)',
  '6.0(2)A8(1)',
  '6.0(2)A8(2)',
  '6.0(2)A8(3)',
  '6.0(2)A8(4)',
  '6.0(2)A8(4a)',
  '6.0(2)A8(5)',
  '6.0(2)A8(6)',
  '6.0(2)A8(7)',
  '6.0(2)A8(7a)',
  '6.0(2)A8(7b)',
  '6.0(2)A8(8)',
  '6.0(2)A8(9)',
  '6.0(2)U1(1)',
  '6.0(2)U1(1a)',
  '6.0(2)U1(2)',
  '6.0(2)U1(3)',
  '6.0(2)U1(4)',
  '6.0(2)U2(1)',
  '6.0(2)U2(2)',
  '6.0(2)U2(3)',
  '6.0(2)U2(4)',
  '6.0(2)U2(5)',
  '6.0(2)U2(6)',
  '6.0(2)U3(1)',
  '6.0(2)U3(2)',
  '6.0(2)U3(3)',
  '6.0(2)U3(4)',
  '6.0(2)U3(5)',
  '6.0(2)U3(6)',
  '6.0(2)U3(7)',
  '6.0(2)U3(8)',
  '6.0(2)U3(9)',
  '6.0(2)U4(1)',
  '6.0(2)U4(2)',
  '6.0(2)U4(3)',
  '6.0(2)U4(4)',
  '6.0(2)U5(1)',
  '6.0(2)U5(2)',
  '6.0(2)U5(3)',
  '6.0(2)U5(4)',
  '6.0(2)U6(1)',
  '6.0(2)U6(10)',
  '6.0(2)U6(1a)',
  '6.0(2)U6(2)',
  '6.0(2)U6(2a)',
  '6.0(2)U6(3)',
  '6.0(2)U6(3a)',
  '6.0(2)U6(4)',
  '6.0(2)U6(4a)',
  '6.0(2)U6(5)',
  '6.0(2)U6(5a)',
  '6.0(2)U6(5b)',
  '6.0(2)U6(5c)',
  '6.0(2)U6(6)',
  '6.0(2)U6(7)',
  '6.0(2)U6(8)',
  '6.0(2)U6(9)',
  '6.1(2)',
  '6.1(2)I1(1)',
  '6.1(2)I1(2)',
  '6.1(2)I1(3)',
  '6.1(2)I2(1)',
  '6.1(2)I2(2)',
  '6.1(2)I2(2a)',
  '6.1(2)I2(2b)',
  '6.1(2)I2(3)',
  '6.1(2)I3(1)',
  '6.1(2)I3(2)',
  '6.1(2)I3(3.78)',
  '6.1(2)I3(3)',
  '6.1(2)I3(3a)',
  '6.1(2)I3(3b)',
  '6.1(2)I3(4)',
  '6.1(2)I3(4a)',
  '6.1(2)I3(4b)',
  '6.1(2)I3(4c)',
  '6.1(2)I3(4d)',
  '6.1(2)I3(4e)',
  '6.1(2)I3(5)',
  '6.1(2)I3(5a)',
  '6.1(2)I3(5b)',
  '6.2(1)',
  '6.2(10)',
  '6.2(11)',
  '6.2(11b)',
  '6.2(11c)',
  '6.2(11d)',
  '6.2(11e)',
  '6.2(12)',
  '6.2(13)',
  '6.2(13a)',
  '6.2(13b)',
  '6.2(14)',
  '6.2(15)',
  '6.2(16)',
  '6.2(17)',
  '6.2(18)',
  '6.2(19)',
  '6.2(2)',
  '6.2(20)',
  '6.2(20a)',
  '6.2(21)',
  '6.2(23)',
  '6.2(2a)',
  '6.2(3)',
  '6.2(5)',
  '6.2(5a)',
  '6.2(5b)',
  '6.2(6)',
  '6.2(6a)',
  '6.2(6b)',
  '6.2(7)',
  '6.2(8)',
  '6.2(8a)',
  '6.2(8b)',
  '6.2(9)',
  '6.2(9a)',
  '6.2(9b)',
  '6.2(9c)',
  '7.0(2)I2(2c)',
  '7.0(3)',
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
  '7.2(0)D1(1)',
  '7.2(1)D1(1)',
  '7.2(2)D1(1)',
  '7.2(2)D1(2)',
  '7.3(0)D1(1)',
  '7.3(0)DX(1)',
  '7.3(0)DY(1)',
  '7.3(1)D1(1)',
  '7.3(1)D1(1B)',
  '7.3(1)DY(1)',
  '7.3(2)D1(1)',
  '7.3(2)D1(2)',
  '7.3(2)D1(3)',
  '7.3(2)D1(3a)',
  '7.3(3)D1(1)',
  '8.0(1)',
  '8.0(1)S2',
  '8.1(1)',
  '8.1(1a)',
  '8.1(2)',
  '8.1(2a)',
  '8.2(1)',
  '8.2(2)'
);

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
'port'     , 0,
'severity' , SECURITY_WARNING,
'version'  , product_info['version'],
'bug_id'   , cbi
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
