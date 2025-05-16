#TRUSTED b0d987ce7f13c40825919bf0c6bb9aaa2b620852aa042b189df25a9e004b58046c27653a2c361ce8aff8c6a91efcb203429d7a3501a6c094d609a8c2b2fd62c9ab02e51fd33a7712bf30c4a8edb8d29c392ad5e6ffa7e133cfaab7c9ced8a41caf9e0d721e30e2d3e52d110144bebab804808122b6a3c9abed41c2f9d11895841b138601c3c37778fe0a1b5c713da1c1571885cb7037a2db3e09b946d379516be2a10505491ddec93def041ea192bae30e8fb2d3fcf043cb6395c3503df271ec059ab6a65b18c44735f75072b828bf2b0cf2f8bdfb48c587ba4c4e9102f7bbbb74c80c868366e5ee271da401ba502427a9f0be84509fd154de98b56633730ead2a255aa2c256aa6b986673de467a5709df3fc49aeeb5a5d46e75f1ec1e0482b257f6862b2d1023e6ea5241e7af18b95bd7c517b5c2c6d9b9a4873aa58207b09775cf6e3c86fefc7c118eb6967b3e9087ede4c31918b1467f34931841444605d62a0724a643dc7a3db53e3878f43f0f985eff1f0639f3965ec9bc1382a5c681ab5a62e995fe2b0a4808704e1b05be19bdc26a04596645b24cd75a041c6d534602d4ac347d1d5318dd859736a6a0976789a839e0b27fe21a99217dd00a8bb5a72ec9e3bb8b7dff2a2f71a08ca90aade09f9b718f2bda96a57e5146547094b0a730989a48d532c98f3c5245e4999b02436d898127dcf30a3d3b824f36a530a450fb
#TRUST-RSA-SHA256 5e35aea5db35ac297fe822d90a3c9c4b059451ce07fc060bf290b355e4d6c718cbc2fc840c9a72137ed6a822917d7972f0db70333f3f17715b90b668bb38c24b2eccb34b610479cadd0356d113768693b873472257b60ab051ebf1bce6f1eacd45881c7ce0ba34cc7b15b0ce174b584853ab64b4bff891aaaf210cf71eca4d5ee20d2e5cf5e6d68d250171718d83349c28f85a48b69928d5232915f0fc4cfc9f5133b3023648e472c5f75b65b4c476771cda0ff48f6802586d518d4fd1859b8867b4f5e1d849a0fe7c03ffea4fdd9a660221c5c7fa2ab62fcf71255095569ff8027e7f2dd0dd4fdf56ce71afdbd886cd0372e3d6a31c6a61ad959f3006bb76d6472f0c9b9a8e9762f0d12f6e2f6d91ec2303446d238da06b7ce64a9108849ab7630b8e956eeb4e6e55739f4e515e10237e9ed10cf8313a7a09632cbcada2827009dd5df3abd67c0c2730de57dd25c41858ba43c31d049690ef0020ed5429dfba2a8936e702bebb52b74562afaa2edd201393d1f4198a9c680127454738d2ca587e1202a855e6bfd7d9481966ebc411ae3a381d2cd5869120518fa9e2206f15bac9a68090c4ad3f5a639f34d719df891fd8d3bfdd0b579def4faba41ad4175ea1d0c7a1636252d3268ab7544dc93acd9acdb5537e07c09e5e61d43cef253dae2da1d0f0450dc137125e95d1d6823b267306f24b130f4a837434ba25dea46fdf4b
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(129946);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/18");

  script_cve_id("CVE-2019-1781", "CVE-2019-1782");
  script_bugtraq_id(108407);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvh20027");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvh20389");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi01445");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi01448");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi91985");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi92126");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi92128");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi92129");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi96522");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi96524");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi96525");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi96526");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190515-fxos-nxos-cmdinj-1781-1782");
  script_xref(name:"IAVA", value:"2019-A-0173");

  script_name(english:"Cisco NX-OS Software Command Injection Vulnerabilities (cisco-sa-20190515-fxos-nxos-cmdinj-1781-1782)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco NX-OS Software is affected by vulnerabilities 
in the CLI that could allow an authenticated, local attacker to execute arbitrary commands on the
underlying operating system of an affected device. This vulnerability is due to insufficient
validation of arguments passed to certain CLI commands. An attacker could exploit this vulnerability
by including malicious input as the argument of an affected command. A successful exploit could allow
the attacker to execute arbitrary commands on the underlying operating system with elevated privileges.
An attacker would need administrator credentials to exploit this vulnerability.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190515-fxos-nxos-cmdinj-1781-1782
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9d66d198");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvh20027");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvh20389");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi01445");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi01448");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi91985");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi92126");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi92128");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi92129");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi96522");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi96524");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi96525");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi96526");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs 
CSCvh20027, CSCvh20389, CSCvi01445, CSCvi01448, CSCvi91985, CSCvi92126, CSCvi92128,
CSCvi92129, CSCvi96522, CSCvi96524, CSCvi96525, CSCvi96526");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1782");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(77);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/15");

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

cbi = '';
if('MDS' >< product_info.device && product_info.model =~ "^(90|70|77)[0-9][0-9]")
  cbi = 'CSCvi01448, CSCvh20389';
else if ('UCS' >< product_info.device && product_info.model =~ "^(62|63)[0-9][0-9]")
  cbi = 'CSCvi96526, CSCvi92129';
else if('Nexus' >< product_info.device)
{
  if(product_info.model =~ "^(30|35|90)[0-9][0-9]")
    cbi = 'CSCvi01445, CSCvh20027, CSCvi96524, CSCvi92126';
  else if(product_info.model =~ "^(36|95)[0-9][0-9]")
    cbi = 'CSCvi96522, CSCvi91985';
  else if(product_info.model =~ "^(55|56|60)[0-9][0-9]")
    cbi = 'CSCvi96525, CSCvi92128';
  else if(product_info.model =~ "^(70|77)[0-9][0-9]")
    cbi = 'CSCvi01448, CSCvh20389';
}
else audit(AUDIT_HOST_NOT, 'affected');

vuln_list = [
  '3.2(3a)A',
  '4.0(0.336)',
  '6.0(2)',
  '6.0(3)',
  '6.0(4)',
  '6.0(2)A1',
  '6.0(2)A1(1)',
  '6.0(2)A1(1a)',
  '6.0(2)A1(1b)',
  '6.0(2)A1(1c)',
  '6.0(2)A1(1d)',
  '6.0(2)A1(1e)',
  '6.0(2)A1(1f)',
  '6.0(2)A1(2d)',
  '6.0(2)A3',
  '6.0(2)A3(1)',
  '6.0(2)A3(2)',
  '6.0(2)A3(4)',
  '6.0(2)A4',
  '6.0(2)A4(1)',
  '6.0(2)A4(2)',
  '6.0(2)A4(3)',
  '6.0(2)A4(4)',
  '6.0(2)A4(5)',
  '6.0(2)A4(6)',
  '6.0(2)A6',
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
  '6.0(2)A7',
  '6.0(2)A7(1)',
  '6.0(2)A7(1a)',
  '6.0(2)A7(2)',
  '6.0(2)A7(2a)',
  '6.0(2)A8',
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
  '6.0(2)A8(10a)',
  '6.0(2)A8(10)',
  '6.2',
  '6.2(2)',
  '6.2(2a)',
  '6.2(6)',
  '6.2(6b)',
  '6.2(8)',
  '6.2(8a)',
  '6.2(8b)',
  '6.2(10)',
  '6.2(12)',
  '6.2(18)',
  '6.2(16)',
  '6.2(14b)',
  '6.2(14)',
  '6.2(14a)',
  '6.2(6a)',
  '6.2(20)',
  '6.2(1)',
  '6.2(3)',
  '6.2(5)',
  '6.2(5a)',
  '6.2(5b)',
  '6.2(7)',
  '6.2(9)',
  '6.2(9a)',
  '6.2(9b)',
  '6.2(9c)',
  '6.2(11)',
  '6.2(11b)',
  '6.2(11c)',
  '6.2(11d)',
  '6.2(11e)',
  '6.2(13)',
  '6.2(13a)',
  '6.2(13b)',
  '6.2(15)',
  '6.2(17)',
  '6.2(19)',
  '6.2(21)',
  '6.2(20a)',
  '7.0',
  '7.0(3)',
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
  '7.0(3)F3(4)',
  '7.0(3)F3(3c)',
  '7.0(3)F3(3b)',
  '7.0(3)I1',
  '7.0(3)I1(1)',
  '7.0(3)I1(1a)',
  '7.0(3)I1(1b)',
  '7.0(3)I1(2)',
  '7.0(3)I1(3)',
  '7.0(3)I1(3a)',
  '7.0(3)I1(3b)',
  '7.0(3)I2',
  '7.0(3)I2(2a)',
  '7.0(3)I2(2b)',
  '7.0(3)I2(2c)',
  '7.0(3)I2(2d)',
  '7.0(3)I2(2e)',
  '7.0(3)I2(3)',
  '7.0(3)I2(4)',
  '7.0(3)I2(5)',
  '7.0(3)I2(1)',
  '7.0(3)I2(1a)',
  '7.0(3)I2(2)',
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
  '7.0(3)I4(8)',
  '7.0(3)I4(8a)',
  '7.0(3)I4(8b)',
  '7.0(3)I4(8z)',
  '7.0(3)I7(5a)',
  '7.0(3)I5',
  '7.0(3)I5(1)',
  '7.0(3)I5(2)',
  '7.0(3)I6',
  '7.0(3)I6(1)',
  '7.0(3)I6(2)',
  '7.0(3)I7',
  '7.0(3)I7(1)',
  '7.0(3)I7(2)',
  '7.0(3)I7(3)',
  '7.0(3)IHD8(0.401)',
  '7.3',
  '7.3(0.2)',
  '7.3(0)D1',
  '7.3(0)D1(1)',
  '7.3(0)DX',
  '7.3(0)DX(1)',
  '7.3(0)DY',
  '7.3(0)DY(1)',
  '7.3(0)N1',
  '7.3(0)N1(1)',
  '7.3(0)N1(1b)',
  '7.3(0)N1(1a)',
  '7.3(1)D1',
  '7.3(1)D1(1B)',
  '7.3(1)D1(1)',
  '7.3(1)DY',
  '7.3(1)DY(1)',
  '7.3(1)N1',
  '7.3(1)N1(0.1)',
  '7.3(1)N1(1)',
  '7.3(2)D1',
  '7.3(2)D1(1A)',
  '7.3(2)D1(1)',
  '7.3(2)D1(2)',
  '7.3(2)D1(3)',
  '7.3(2)D1(3a)',
  '7.3(2)N1',
  '7.3(2)N1(0.296)',
  '7.3(2)N1(1)',
  '7.3(3)N1',
  '7.3(3)N1(1)',
  '8.2',
  '8.2(1)',
  '8.2(2)',
  '7.3(3)D1'
];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , cbi
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:vuln_list,
  switch_only:TRUE
);
