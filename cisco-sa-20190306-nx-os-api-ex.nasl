#TRUSTED 361993e4c7d8af3d41b12d9b4d78a134d84c6823d2f6f5625f2f559af19fce0c2612d228914bf921bd36c5e823ec1933c8aa235caf8b27854a979cc1102818146adda052f077ec1e06710975cbe9a4e85e446a10b50dee2e498d59e20314404e3957034c6d6e223688d4aa8ab088b115ce42d763e0858721dda14175622f779cf8ecf8f6745094857b977377b3a3f0b6e47745e719e2fa3c88482da75dc5b6f452967eb0aa3da9a208a3f32c18912c2ce4829ecbbb3b8222cfaaf68e698e04c0953bacf835e99d983db5345d83b93a786afc0087aae9e0c887308ca49182e9a41859e98ff4a82f76263b808a890bc6321f53ad350dde68cbbc26ef8649dfa77ed7a5a96680dd3fd192da11687d517bd9e1529789692456e15b0ee1aba048271b0f16f2a2ec584ab6696b2ac28eeaa68f0f714f67a7e5ea82916563aac4df5a34e605c6089181570da7af9f7391e2c4a87f5f419eeafdf9541a8a5d40cd7a5b3e44986bde12124222580ff0e98bd1bd21bb23bf0063624b43b76709ad1314a14fb02255e4f78bb46f6428a3475f82f4e140886a61e6b137c50926309bd5320901e673c19d7b924eded99641a9e1c1afec946f4b77ed58b64d89c436b5d2b6529590cfc69f4ddf411742a980db7dcd1b6d353f0594cdae8f249180c013ef3a76d673f9a65ed0cb8e545cbad360f033980dd34383d2d3b1629b1b2e488f8de51162
#TRUST-RSA-SHA256 4af98db2c3a54e4df9f4080fe834ded208e638e35d802538bae98e2037026896db2d9b5e564a3ccdbed328373aac61f0073a6d3826e9200e8ad34cb22fdec31348a0c93f6038e21e9e0c63116cb1ed98cdfaceea8f7c942c413e2aa681b4d5465554f7547e90d12f6bc4597dfeaeffa1cba2b8b9a96ece11ab84c8070279f42ca932451b9be3427c09191afdabadbc8a8d9aaa98694635f47c121f848a95df4be4bb98012a832f8a29f933249f09ca1968e6f425cbc81bcf27baed138221fa91c062a2f5e4fdef9cd1abd88c169888b7efd9631b40f19bf5e852ff5602eb6ac8352ef14508ae46f284cccd2199563e622d00bf24009535902e2c5b166b2e63ecd3e66548221811272b777a9441972cd17551b91b5d0e797ca53c57e1edaaced9d548855332e6f8d4175d7d58dee8e841e86d56df6610860e44eeb1eede72218cbd65f9987a59eb25ed946c2b8ed74d941978cefcbc5d7c8ac0b1b2d641da22e74b25416783389a522369df226fa804e779ff6a7872c671738339a45f5c33559947f4d3ef51fad1dc0295bd984d00d22f5cc12a2876eb775094ca38eaea808cefeb010dc94086bf55cb2fa5cbc24c0bf8d2ad51a08e92642d2ca96a2d1ba49ccfbe9324ae7033d412908e126a4dd7e708e29d77c84a7e7941be8bb99df91f2270f2ed4048865165ffcff96eae534936057954d5297c6969c8953319b4d9dc445d
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(132318);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/02");

  script_cve_id("CVE-2019-1605");
  script_bugtraq_id(107313);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvh77526");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi99224");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi99225");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi99227");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi99228");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190306-nx-os-api-ex");

  script_name(english:"Cisco NX-OS Software NX-API Arbitrary Code Execution Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco NX-OS Software is affected by a vulnerability in the NX-API feature of
Cisco NX-OS Software that could allow an authenticated, local attacker to execute arbitrary code as root. The
vulnerability is due to incorrect input validation in the NX-API feature. An attacker could exploit this vulnerability
by sending a crafted HTTP or HTTPS request to an internal service on an affected device that has the NX-API feature
enabled. A successful exploit could allow the attacker to cause a buffer overflow and execute arbitrary code as root.
Note: The NX-API feature is disabled by default.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190306-nxos-api-ex
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4326b1dc");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-70757");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvh77526");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi99224");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi99225");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi99227");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi99228");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvh77526, CSCvi99224, CSCvi99225, CSCvi99227, and
CSCvi99228");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1605");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/20");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Device", "Host/Cisco/NX-OS/Model", "Host/Cisco/NX-OS/Version");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco NX-OS Software');

cbi = '';
if ('MDS' >< product_info.device && product_info.model =~ '^90[0-9][0-9]')
  cbi = 'CSCvi99225';
else if ('Nexus' >< product_info.device)
{
  if (product_info.model =~ '^[39]0[0-9][0-9]')
    cbi = 'CSCvh77526';
  else if (product_info.model =~ '^(36|95)[0-9][0-9]')
    cbi = 'CSCvi99224';
  else if (product_info.model =~ '^7[07][0-9][0-9]')
    cbi = 'CSCvi99225';
  else if (product_info.model =~ '^35[0-9][0-9]')
    cbi = 'CSCvi99227';
  else if (product_info.model =~ '^(20|5[56]|60)[0-9][0-9]')
    cbi = 'CSCvi99228';
  else
    audit(AUDIT_HOST_NOT, 'affected');
}
else
  audit(AUDIT_HOST_NOT, 'affected');

version_list=make_list(
  '7.3(2)D1(3a)',
  '7.3(2)D1(3)',
  '7.3(2)D1(2)',
  '7.3(2)D1(1)',
  '7.3(1)N1(1)',
  '7.3(1)DY(1)',
  '7.3(1)D1(1)',
  '7.3(0)N1(1)',
  '7.3(0)DY(1)',
  '7.3(0)DX(1)',
  '7.3(0)D1(1)',
  '7.2(2)D1(2)',
  '7.2(2)D1(1)',
  '7.2(1)D1(1)',
  '7.2(0)D1(1)',
  '7.0(3)IX1(2a)',
  '7.0(3)IX1(2)',
  '7.0(3)I6(2)',
  '7.0(3)I6(1)',
  '7.0(3)I5(2)',
  '7.0(3)I5(1)',
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
  '7.0(3)F3(3a)',
  '7.0(3)F3(3)',
  '7.0(3)F3(2)',
  '7.0(3)F3(1)',
  '7.0(3)F2(2)',
  '7.0(3)F2(1)',
  '7.0(3)F1(1)',
  '7.0(2)I2(2c)',
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
  '6.0(2)A8(7b)',
  '6.0(2)A8(7a)',
  '6.0(2)A8(7)',
  '6.0(2)A8(6)',
  '6.0(2)A8(5)',
  '6.0(2)A8(4a)',
  '6.0(2)A8(4)',
  '6.0(2)A8(3)',
  '6.0(2)A8(2)',
  '6.0(2)A8(1)',
  '6.0(2)A7(2a)',
  '6.0(2)A7(2)',
  '6.0(2)A7(1a)',
  '6.0(2)A7(1)',
  '6.0(2)A6(8)',
  '6.0(2)A6(7)',
  '6.0(2)A6(6)',
  '6.0(2)A6(5b)',
  '6.0(2)A6(5a)',
  '6.0(2)A6(5)',
  '6.0(2)A6(4a)',
  '6.0(2)A6(4)',
  '6.0(2)A6(3a)',
  '6.0(2)A6(3)',
  '6.0(2)A6(2a)',
  '6.0(2)A6(2)',
  '6.0(2)A6(1a)',
  '6.0(2)A6(1)',
  '6.0(2)A4(6)',
  '6.0(2)A4(5)',
  '6.0(2)A4(4)',
  '6.0(2)A4(3)',
  '6.0(2)A4(2)',
  '6.0(2)A4(1)',
  '6.0(2)A3(4)',
  '6.0(2)A3(2)',
  '6.0(2)A3(1)',
  '6.0(2)A1(2d)',
  '6.0(2)A1(1f)',
  '6.0(2)A1(1e)',
  '6.0(2)A1(1d)',
  '6.0(2)A1(1c)',
  '6.0(2)A1(1b)',
  '6.0(2)A1(1a)',
  '6.0(2)A1(1)',
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
  '5.0(3)A1(2a)',
  '5.0(3)A1(2)',
  '5.0(3)A1(1)'
);

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['nxos_nxapi'];


reporting = make_array(
'port'     , 0,
'severity' , SECURITY_HOLE,
'version'  , product_info['version'],
'bug_id'   , cbi
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
