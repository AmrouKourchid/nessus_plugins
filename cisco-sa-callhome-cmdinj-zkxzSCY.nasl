#TRUSTED 4d687eef5abecb8f539b572dc4f727cd5c1c4bd5100a0befef5378b63ef4209a62576d9694fac83ad1055583e7bde1366a28d3277f97ca2f8bd49bcfd6b240e7557e03724eb7770db4530bbe104b61d928586c329e43ab10da95149907757f7479c4b4c5e7bf1abd2b9e75619ade7e6747c0b457f1648a89b7d8a13052eff1d4c2499eca254cba9e89a45de67abfda735093e6108303eb2ac6d2d801b8e4072339094d32bbbae4c65143369801284916642d0dc6c54b362922ac51401d55bb8d1eb38f3afd2d2f023948d87bcdbb35ff41ae2711c50bced9d7978a67f4f43a5b416e90e20c3e39176cfee6f4b87b0f34617586b970339f0ebb4eab3038dfd28217a499a3b894a8afd8710c9e8abc5142746023eb6cf723c03bc23ae33e6365006fe2a49d6899f219068e87b93807cbdc74e87f0e3939e1cb81300159bc40922fa5718023749a42a10782d9843c2172efa5497d15022261bb4510a9a9ae0d9b1ea7ed98a8a29e3dc54cc178eac3dec6ea73b35f46bd4d5653782a10e16b84832feaa4d1ab3d8f13437196eee95a39d2c278aae8c9d539770310e601fb30521b1deaef5c481d625cad392133e4eedcd54ef0352f476078c3b68a83000f15d6cb9b3419808bcce4f4e08f7a388f1705e80248cea7215e71d89e4d26efedee78e78b9452e523499974bdb9675731794486e1bd34cc04039768e744b2d9afadd635cf
#TRUST-RSA-SHA256 333a3cadebed8d009e37e2a2249535e3779636318cf642fb23e8e850b81dc8974ef991cfd3b8e8a885146c84ed1fca576011ea391333918a8e8a6fc0c43a3fd51fdc370422f7d1b08aac6c69756412b36eb49b61bcbc53a2b727041721287bf1beda6b7f09aa557639fb7c06e12d636f1233a3160de33a22ec65c64b712735b8fdbb6fc25911154fc563fd3219305a706cccef6c6d626841129b65dbb2de620466b9fa987a157b77360cbb5a460995ef74479ef047eb6c88c645b374814aa476d6c0fb9ed8c0730dad5d75091510bfee16f604e5a2998b70284ea180de364bf8339c2c6121c28241447e097b86c78ec7af65d95c979c5341f2fe201118d771558a777e35618abd5eccb7710c35f69e09effbdc38ed088f16bbb1dc0c25a63cff901e327af2a496c583f51b7e4d6e63d7e1a3b6c2d9e4b89b7d4b4e522cc5a2554d6ec35d04fb1acd5bcd011fd89cad30bcc0e9354c1861ea188fa6e42d76a35eed48bbea3f6debf8caa10e94a951984fd3026b024c6e4614178915dda3a6d4757990711e361ed2acd50125cc6a5580c79e0aad0b74cf64bb20873fc922f58cec483663e0443fae4ce13b45e124078655ddf2dad57e4ba0161b4c6f753f4461bbc1ede1f1f5454ac4b3ba743877c6a3f531ffbd94f6b2cb4345fdbce59616751ad2fb49de8791a14c0a333b32d04d0c4e31740367b65642dec569e765d099126e
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(140202);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/08");

  script_cve_id("CVE-2020-3454");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve15011");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvg11715");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvg11732");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvg11752");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvh85161");
  script_xref(name:"CISCO-SA", value:"cisco-sa-callhome-cmdinj-zkxzSCY");
  script_xref(name:"IAVA", value:"2020-A-0394-S");

  script_name(english:"Cisco NX-OS Software Call Home Command Injection (cisco-sa-callhome-cmdinj-zkxzSCY)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco NX-OS Software is affected by a command injection vulnerability due to
insufficient input validation of specific Call Home configuration parameters when configured for transport method
HTTP. An authenticated, remote attacker could modify parameters within the Call Home configuration in order to execute
arbitrary commands with root privileges on the underlying OS. Please see the included Cisco BIDs and Cisco Security
Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-callhome-cmdinj-zkxzSCY
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?651817a0");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74239");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve15011");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvg11715");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvg11732");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvg11752");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvh85161");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCve15011, CSCvg11715, CSCvg11732, CSCvg11752,
CSCvh85161");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3454");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/03");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Model", "Host/Cisco/NX-OS/Device");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

product_info = cisco::get_product_info(name:'Cisco NX-OS Software');

if (('MDS' >!< product_info.device || product_info.model !~ "^90[0-9][0-9]") &&
  ('Nexus' >!< product_info.device || product_info.model !~ "^([39][0-9]{3})|(55|56|60|70)[0-9]{2}"))
audit(AUDIT_HOST_NOT, 'affected');

if (!(empty_or_null(get_kb_list('Host/aci/*'))))
  audit(AUDIT_HOST_NOT, 'an affected model due to ACI mode');

cbi = NULL;
version_list = NULL;

if ('MDS' >< product_info.device && product_info.model =~ "^90[0-9]{2}")
{
  cbi = 'CSCvh85161';
  version_list = make_list(
    '5.0(1a)',
    '5.0(1b)',
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
    '6.2(1)',
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
    '6.2(17a)',
    '6.2(19)',
    '6.2(21)',
    '6.2(23)',
    '6.2(3)',
    '6.2(5)',
    '6.2(5a)',
    '6.2(5b)',
    '6.2(7)',
    '6.2(9)',
    '6.2(9a)',
    '6.2(9b)',
    '6.2(9c)',
    '7.3(0)D1(1)',
    '7.3(0)DY(1)',
    '7.3(1)D1(1)',
    '7.3(1)DY(1)',
    '8.1(1)',
    '8.1(1a)',
    '8.1(1b)',
    '8.2(1)',
    '8.2(2)'
  );
}
else if ('Nexus' >< product_info.device)
{
  if (product_info.model =~ "^3[0-9]{3}")
  {
    cbi = 'CSCvg11715,CSCvg11752';
    version_list = make_list(
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
      '6.0(2)U6(10a)',
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
      '6.1(2)I2(2a)',
      '6.1(2)I2(2b)',
      '6.1(2)I3(1)',
      '6.1(2)I3(2)',
      '6.1(2)I3(3)',
      '6.1(2)I3(3a)',
      '6.1(2)I3(4)',
      '6.1(2)I3(4a)',
      '6.1(2)I3(4b)',
      '6.1(2)I3(4c)',
      '6.1(2)I3(4d)',
      '6.1(2)I3(4e)',
      '7.0(3)F3(1)',
      '7.0(3)F3(2)',
      '7.0(3)I1(1)',
      '7.0(3)I1(1a)',
      '7.0(3)I1(1b)',
      '7.0(3)I1(1z)',
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
      '7.0(3)I2(2r)',
      '7.0(3)I2(2s)',
      '7.0(3)I2(2v)',
      '7.0(3)I2(2w)',
      '7.0(3)I2(2x)',
      '7.0(3)I2(2y)',
      '7.0(3)I2(3)',
      '7.0(3)I2(4)',
      '7.0(3)I2(5)',
      '7.0(3)I3(1)',
      '7.0(3)I4(1)',
      '7.0(3)I4(1t)',
      '7.0(3)I4(2)',
      '7.0(3)I4(3)',
      '7.0(3)I4(4)',
      '7.0(3)I4(5)',
      '7.0(3)I4(6)',
      '7.0(3)I4(6t)',
      '7.0(3)I4(7)',
      '7.0(3)I5(1)',
      '7.0(3)I5(2)',
      '7.0(3)I5(3)',
      '7.0(3)I5(3a)',
      '7.0(3)I5(3b)',
      '7.0(3)I6(1)',
      '7.0(3)I6(2)',
      '7.0(3)I7(1)',
      '7.0(3)IC4(4)',
      '7.0(3)IM7(2)',
      '7.0(3)IX1(2)',
      '7.0(3)IX1(2a)'
    );
  }
  else if (product_info.model =~ "^5[0-9]{3}")
  {
    cbi = 'CSCve15011';
    version_list = make_list(
      '5.2(1)N1(1)',
      '5.2(1)N1(1a)',
      '5.2(1)N1(1b)',
      '5.2(1)N1(2)',
      '5.2(1)N1(2a)',
      '5.2(1)N1(3)',
      '5.2(1)N1(4)',
      '5.2(1)N1(5)',
      '5.2(1)N1(6)',
      '5.2(1)N1(7)',
      '5.2(1)N1(8)',
      '5.2(1)N1(8a)',
      '5.2(1)N1(8b)',
      '5.2(1)N1(9)',
      '5.2(1)N1(9a)',
      '5.2(1)N1(9b)',
      '6.0(2)N1(1)',
      '6.0(2)N1(1a)',
      '6.0(2)N1(2)',
      '6.0(2)N1(2a)',
      '6.0(2)N2(1)',
      '6.0(2)N2(1b)',
      '6.0(2)N2(2)',
      '6.0(2)N2(3)',
      '6.0(2)N2(4)',
      '6.0(2)N2(5)',
      '6.0(2)N2(5a)',
      '6.0(2)N2(5b)',
      '6.0(2)N2(6)',
      '6.0(2)N2(7)',
      '7.0(0)N1(1)',
      '7.0(1)N1(1)',
      '7.0(2)N1(1)',
      '7.0(3)N1(1)',
      '7.0(4)N1(1)',
      '7.0(4)N1(1a)',
      '7.0(5)N1(1)',
      '7.0(5)N1(1a)',
      '7.0(6)N1(1)',
      '7.0(6)N1(2s)',
      '7.0(6)N1(3s)',
      '7.0(6)N1(4s)',
      '7.0(7)N1(1)',
      '7.0(7)N1(1a)',
      '7.0(7)N1(1b)',
      '7.0(8)N1(1)',
      '7.0(8)N1(1a)',
      '7.1(0)N1(1)',
      '7.1(0)N1(1a)',
      '7.1(0)N1(1b)',
      '7.1(1)N1(1)',
      '7.1(1)N1(1a)',
      '7.1(2)N1(1)',
      '7.1(2)N1(1a)',
      '7.1(3)N1(1)',
      '7.1(3)N1(2)',
      '7.1(3)N1(2a)',
      '7.1(3)N1(3)',
      '7.1(3)N1(4)',
      '7.1(3)N1(5)',
      '7.1(4)N1(1)',
      '7.1(4)N1(1a)',
      '7.1(4)N1(1c)',
      '7.1(4)N1(1d)',
      '7.1(5)N1(1)',
      '7.2(0)N1(1)',
      '7.2(1)N1(1)',
      '7.3(0)N1(1)',
      '7.3(0)N1(1a)',
      '7.3(0)N1(1b)',
      '7.3(1)N1(1)',
      '7.3(2)N1(1)',
      '7.3(2)N1(1b)',
      '7.3(2)N1(1c)'
    );
  }
    else if (product_info.model =~ "^6[0-9]{3}")
  {
    cbi = 'CSCve15011';
    version_list = make_list(
      '6.0(2)N1(1)',
      '6.0(2)N1(1a)',
      '6.0(2)N1(2)',
      '6.0(2)N1(2a)',
      '6.0(2)N2(1)',
      '6.0(2)N2(1b)',
      '6.0(2)N2(2)',
      '6.0(2)N2(3)',
      '6.0(2)N2(4)',
      '6.0(2)N2(5)',
      '6.0(2)N2(5a)',
      '6.0(2)N2(5b)',
      '6.0(2)N2(6)',
      '6.0(2)N2(7)',
      '7.0(0)N1(1)',
      '7.0(1)N1(1)',
      '7.0(2)N1(1)',
      '7.0(3)N1(1)',
      '7.0(4)N1(1)',
      '7.0(4)N1(1a)',
      '7.0(5)N1(1)',
      '7.0(5)N1(1a)',
      '7.0(6)N1(1)',
      '7.0(6)N1(2s)',
      '7.0(6)N1(3s)',
      '7.0(6)N1(4s)',
      '7.0(7)N1(1)',
      '7.0(7)N1(1a)',
      '7.0(7)N1(1b)',
      '7.0(8)N1(1)',
      '7.0(8)N1(1a)',
      '7.1(0)N1(1)',
      '7.1(0)N1(1a)',
      '7.1(0)N1(1b)',
      '7.1(1)N1(1)',
      '7.1(1)N1(1a)',
      '7.1(2)N1(1)',
      '7.1(2)N1(1a)',
      '7.1(3)N1(1)',
      '7.1(3)N1(2)',
      '7.1(3)N1(2a)',
      '7.1(3)N1(3)',
      '7.1(3)N1(4)',
      '7.1(3)N1(5)',
      '7.1(4)N1(1)',
      '7.1(4)N1(1a)',
      '7.1(4)N1(1c)',
      '7.1(4)N1(1d)',
      '7.1(5)N1(1)',
      '7.2(0)N1(1)',
      '7.2(1)N1(1)',
      '7.3(0)N1(1)',
      '7.3(0)N1(1a)',
      '7.3(0)N1(1b)',
      '7.3(1)N1(1)',
      '7.3(2)N1(1)',
      '7.3(2)N1(1b)',
      '7.3(2)N1(1c)'
    );
  }
  else if (product_info.model =~ "^7[0-9]{3}")
  {
    cbi = 'CSCvg11732';
    version_list = make_list(
      '5.2(1)',
      '5.2(3)',
      '5.2(3a)',
      '5.2(4)',
      '5.2(5)',
      '5.2(7)',
      '5.2(9)',
      '5.2(9a)',
      '6.2(10)',
      '6.2(12)',
      '6.2(14)',
      '6.2(14a)',
      '6.2(14b)',
      '6.2(16)',
      '6.2(18)',
      '6.2(2)',
      '6.2(20)',
      '6.2(20a)',
      '6.2(2a)',
      '6.2(6)',
      '6.2(6a)',
      '6.2(6b)',
      '6.2(8)',
      '6.2(8a)',
      '6.2(8b)',
      '7.2(0)D1(1)',
      '7.2(1)D1(1)',
      '7.2(2)D1(1)',
      '7.2(2)D1(2)',
      '7.2(2)D1(3)',
      '7.2(2)D1(4)',
      '7.3(0)D1(1)',
      '7.3(0)DX(1)',
      '7.3(1)D1(1)',
      '7.3(2)D1(1)',
      '7.3(2)D1(1d)',
      '7.3(2)D1(2)',
      '7.3(2)D1(3)',
      '7.3(2)D1(3a)',
      '8.0(1)',
      '8.1(1)',
      '8.1(2)',
      '8.1(2a)',
      '8.2(1)',
      '8.2(2)'
    );
  }
  else if (product_info.model =~ "^9[0-9]{3}")
  {
    cbi = 'CSCvg11715,CSCvg11752';
    version_list = make_list(
      '6.1(2)I1(2)',
      '6.1(2)I1(3)',
      '6.1(2)I2(1)',
      '6.1(2)I2(2)',
      '6.1(2)I2(2a)',
      '6.1(2)I2(2b)',
      '6.1(2)I2(3)',
      '6.1(2)I3(1)',
      '6.1(2)I3(2)',
      '6.1(2)I3(3)',
      '6.1(2)I3(3a)',
      '6.1(2)I3(4)',
      '6.1(2)I3(4a)',
      '6.1(2)I3(4b)',
      '6.1(2)I3(4c)',
      '6.1(2)I3(4d)',
      '6.1(2)I3(4e)',
      '6.1(2)I3(5)',
      '6.1(2)I3(5a)',
      '6.1(2)I3(5b)',
      '7.0(3)F1(1)',
      '7.0(3)F2(1)',
      '7.0(3)F2(2)',
      '7.0(3)F3(1)',
      '7.0(3)I1(1)',
      '7.0(3)I1(1a)',
      '7.0(3)I1(1b)',
      '7.0(3)I1(1z)',
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
      '7.0(3)I2(2r)',
      '7.0(3)I2(2s)',
      '7.0(3)I2(2v)',
      '7.0(3)I2(2w)',
      '7.0(3)I2(2x)',
      '7.0(3)I2(2y)',
      '7.0(3)I2(3)',
      '7.0(3)I2(4)',
      '7.0(3)I2(5)',
      '7.0(3)I3(1)',
      '7.0(3)I4(1)',
      '7.0(3)I4(1t)',
      '7.0(3)I4(2)',
      '7.0(3)I4(3)',
      '7.0(3)I4(4)',
      '7.0(3)I4(5)',
      '7.0(3)I4(6)',
      '7.0(3)I4(6t)',
      '7.0(3)I4(7)',
      '7.0(3)I5(1)',
      '7.0(3)I5(2)',
      '7.0(3)I5(3)',
      '7.0(3)I5(3a)',
      '7.0(3)I5(3b)',
      '7.0(3)I6(1)',
      '7.0(3)I6(2)',
      '7.0(3)I7(1)',
      '7.0(3)IC4(4)',
      '7.0(3)IM3(1)',
      '7.0(3)IM3(2)',
      '7.0(3)IM3(2a)',
      '7.0(3)IM3(2b)',
      '7.0(3)IM3(3)'
    );
  }
  else audit(AUDIT_HOST_NOT, 'affected');
}
else audit(AUDIT_HOST_NOT, 'affected');

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['callhome_destination-profile_http'];

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
  vuln_versions:version_list
);

