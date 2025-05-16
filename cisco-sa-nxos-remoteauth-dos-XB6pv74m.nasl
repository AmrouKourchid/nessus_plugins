#TRUSTED 7c9cdf4cb152cc9f95f8ffe6088c9c150c5311e212047b9680dfc7cafe2ac60c04b1be15abce976122f4d9b778ffe2c2b3cc59d3c140193904f2b8908a3007eb5039982e4b2179bf5e4debd5565acc9c33da1541dfcf489e6a06fc6a5a838e2cb2ba6445840873b3b9855ccbe8d24741c758a60d40509c9937b5c30f42731a847574b3fb7d9d7fec6f83abb35c62951e78a2db408fe67a27929eb436a4babd3bfcd0c787a08b192c8c80c0450957097ec8856d9cfb55685bf26c16c939a9569c115b6d05ed689c39d5cf481c770cc63e2c475fb21775daaf2e52d73729a16c17af7c9ea04d3196d53cf2a4debe7d09c7acb6ea1e9bb633d136438424f1917efb6271ee5c219f473989b205e76a776934eabc70eecd583086156b83451f4c89239d52041eb3384f862661630a5e904d756489baed569a23ba0095604c4fdff7a3eede1be81983a3550a820584778c83a2028fc536c97ec36cff58e189d48e76211bd8b0670b1f177d5185faec40efa4308a3d742b006d0c5daf3c8172bbc844f51ae9e071b3f2764a51fbef1960c029351987dbc9ac5b79773b61539a538cfef0d179744c0df7e13878ce0fe085f0a29e118aa073d2bc2ca176661aaf4e19643d89400e42e94e65ecdb0962232d3bb0c5347dc03840d148fbd89fbac6a2f34a1d095e4df721a0639d08755fe369015852f77029a7bf397048e0228cfcf02a560c
#TRUST-RSA-SHA256 86bb35418848a48d8e2eccd0b27e0eeb8afdd6c082697dfd446f40a2fb57319477de711b86d4327187d91408d482e73b9b71ef2033889b896afe4772f3960a3ccd0ae8ec0e01c701b4e3bbbe95ddde87e88a463e486f8a1815ebd3884375dcdf99c1622e859caa2df063ad2cb75126784c530d8abe79f4479148e321780c6b12731559cfd23b74e6087d64c6bc5e3c73ce816f37f625ad221b86433428715792bcd529312d36eefa882694f3ac1eba9995d90d60b9f18846ff897f02e45d88d5a0afd64f6020ea52e1af9f7495d6eba471b1c34b9466a4ad1b2cc7fd9793b51a9cc9a22744c035422502c0f2414fa0a7b0472076ca8be719d88a30762231f683d2a19524ff280c7754f0231c72a9216c48afb4cefdbb3b7900bce22dec289c1f4c1fa34b94889adac86dcb1669a8d0389aaf7cbeb1e3a0d7ad29bffb956c3692b25765967ab1bbd64a6592b2e8dcf4687997ee9d9d147100dd1a5ee092bf0d8163ae0285ec70da829f1520da57fc2dd327b9b7050f3f2b31576adedd0207f5aed0e0fd0fd32ccae45fe04473fee9c2bf826bbbb177ebad37671f33f4c8fb50575b934e5fdafdc9ce85053420ac81a9a60cb4c7a2f19b20bb6ba5f7fe5b8ffa34abfd2d9fb5da7f17c22b53e3409ecbb356745ec1e89022965dcea4081de40b5fb17a3dee4274ce0b63e08d84a4b0881896184e1bba2a0d21e83c7a4eca939825
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(180229);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/25");

  script_cve_id("CVE-2023-20168");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe72368");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe72648");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe72670");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe72673");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe72674");
  script_xref(name:"CISCO-SA", value:"cisco-sa-nxos-remoteauth-dos-XB6pv74m");
  script_xref(name:"IAVA", value:"2023-A-0439");

  script_name(english:"Cisco NX-OS Software TACACS+ or RADIUS Remote Authentication Directed Request DoS (cisco-sa-nxos-remoteauth-dos-XB6pv74m)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability in TACACS+ and RADIUS remote authentication for Cisco NX-OS Software could allow an unauthenticated, 
local attacker to cause an affected device to unexpectedly reload. This vulnerability is due to incorrect input 
validation when processing an authentication attempt if the directed request option is enabled for TACACS+ or RADIUS. 
An attacker could exploit this vulnerability by entering a crafted string at the login prompt of an affected device. 
A successful exploit could allow the attacker to cause the affected device to unexpectedly reload, resulting in a 
denial of service (DoS) condition.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nxos-remoteauth-dos-XB6pv74m
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?da4d94d6");
  # https://sec.cloudapps.cisco.com/security/center/viewErp.x?alertId=ERP-75058
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d5b1feb9");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwe72368");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwe72648");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwe72670");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwe72673");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwe72674");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCwe72368, CSCwe72648, CSCwe72670, CSCwe72673,
CSCwe72674");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20168");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/08/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/08/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/08/29");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Model", "Host/Cisco/NX-OS/Device");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco NX-OS Software');


if (('Nexus' >!< product_info.device || product_info.model !~ "(^1[0-9]{3}V*$|^5[56][0-9]{2}$|^[3679][0-9]{3}$)") &&
    ('MDS' >!< product_info.device || product_info.model !~ "^9[0-9]{3}"))
  audit(AUDIT_HOST_NOT, 'affected');

var version_list = [];

if ('Nexus' >< product_info.device && product_info.model =~ "^1[0-9]{2,3}")
{
  version_list = make_list(
    '4.2(1)SV1(4)',
    '4.2(1)SV1(4a)',
    '4.2(1)SV1(4b)',
    '4.2(1)SV1(5.1)',
    '4.2(1)SV1(5.1a)',
    '4.2(1)SV1(5.2)',
    '4.2(1)SV1(5.2b)',
    '4.2(1)SV2(1.1)',
    '4.2(1)SV2(1.1a)',
    '4.2(1)SV2(2.1)',
    '4.2(1)SV2(2.1a)',
    '4.2(1)SV2(2.2)',
    '4.2(1)SV2(2.3)',
    '5.2(1)SM1(5.1)',
    '5.2(1)SM1(5.2)',
    '5.2(1)SM1(5.2a)',
    '5.2(1)SM1(5.2b)',
    '5.2(1)SM1(5.2c)',
    '5.2(1)SM3(1.1)',
    '5.2(1)SM3(1.1a)',
    '5.2(1)SM3(1.1b)',
    '5.2(1)SM3(1.1c)',
    '5.2(1)SM3(2.1)',
    '5.2(1)SV3(1.4)',
    '5.2(1)SV3(1.1)',
    '5.2(1)SV3(1.3)',
    '5.2(1)SV3(1.5a)',
    '5.2(1)SV3(1.5b)',
    '5.2(1)SV3(1.6)',
    '5.2(1)SV3(1.10)',
    '5.2(1)SV3(1.15)',
    '5.2(1)SV3(2.1)',
    '5.2(1)SV3(2.5)',
    '5.2(1)SV3(2.8)',
    '5.2(1)SV3(3.1)',
    '5.2(1)SV3(1.2)',
    '5.2(1)SV3(1.4b)',
    '5.2(1)SV3(3.15)',
    '5.2(1)SV3(4.1)',
    '5.2(1)SV3(4.1a)',
    '5.2(1)SV3(4.1b)',
    '5.2(1)SV3(4.1c)',
    '5.2(1)SK3(1.1)',
    '5.2(1)SK3(2.1)',
    '5.2(1)SK3(2.2)',
    '5.2(1)SK3(2.2b)',
    '5.2(1)SK3(2.1a)',
    '5.2(1)SV5(1.1)',
    '5.2(1)SV5(1.2)',
    '5.2(1)SV5(1.3)',
    '5.2(1)SV5(1.3a)',
    '5.2(1)SV5(1.3b)',
    '5.2(1)SV5(1.3c)'
  );
}

if ('Nexus' >< product_info.device && product_info.model =~ "^3[0-9]{2,3}")
{
  version_list = make_list(
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
    '6.0(2)A8(10a)',
    '6.0(2)A8(10)',
    '6.0(2)A8(11)',
    '6.0(2)A8(11a)',
    '6.0(2)A8(11b)',
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
    '6.0(2)U6(2)',
    '6.0(2)U6(3)',
    '6.0(2)U6(4)',
    '6.0(2)U6(5)',
    '6.0(2)U6(6)',
    '6.0(2)U6(7)',
    '6.0(2)U6(8)',
    '6.0(2)U6(1a)',
    '6.0(2)U6(2a)',
    '6.0(2)U6(3a)',
    '6.0(2)U6(4a)',
    '6.0(2)U6(5a)',
    '6.0(2)U6(5b)',
    '6.0(2)U6(5c)',
    '6.0(2)U6(9)',
    '6.0(2)U6(10)',
    '6.0(2)U6(10a)',
    '7.0(3)F3(1)',
    '7.0(3)F3(2)',
    '7.0(3)F3(3)',
    '7.0(3)F3(3a)',
    '7.0(3)F3(4)',
    '7.0(3)F3(3c)',
    '7.0(3)F3(5)',
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
    '7.0(3)I2(2r)',
    '7.0(3)I2(2s)',
    '7.0(3)I2(2v)',
    '7.0(3)I2(2w)',
    '7.0(3)I2(2x)',
    '7.0(3)I2(2y)',
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
    '7.0(3)I4(1t)',
    '7.0(3)I4(6t)',
    '7.0(3)I4(9)',
    '7.0(3)I5(1)',
    '7.0(3)I5(2)',
    '7.0(3)I5(3)',
    '7.0(3)I5(3a)',
    '7.0(3)I5(3b)',
    '7.0(3)I6(1)',
    '7.0(3)I6(2)',
    '7.0(3)I7(1)',
    '7.0(3)I7(2)',
    '7.0(3)I7(3)',
    '7.0(3)I7(4)',
    '7.0(3)I7(5)',
    '7.0(3)I7(5a)',
    '7.0(3)I7(3z)',
    '7.0(3)I7(6)',
    '7.0(3)I7(6z)',
    '7.0(3)I7(7)',
    '7.0(3)I7(8)',
    '7.0(3)I7(9)',
    '7.0(3)I7(9w)',
    '7.0(3)I7(10)',
    '9.2(1)',
    '9.2(2)',
    '9.2(2t)',
    '9.2(3)',
    '9.2(3y)',
    '9.2(4)',
    '9.2(2v)',
    '7.0(3)IC4(4)',
    '7.0(3)IM7(2)',
    '9.3(1)',
    '9.3(2)',
    '9.3(3)',
    '9.3(4)',
    '9.3(5)',
    '9.3(6)',
    '9.3(7)',
    '9.3(7k)',
    '9.3(7a)',
    '9.3(8)',
    '9.3(9)',
    '9.3(10)',
    '9.3(11)',
    '10.1(1)',
    '10.1(2)',
    '10.1(2t)',
    '10.2(1)',
    '10.2(2)',
    '10.2(3)',
    '10.2(3t)',
    '10.2(4)',
    '10.2(5)',
    '10.3(1)',
    '10.3(2)'
  );
}

if ('Nexus' >< product_info.device && product_info.model =~ "^7[0-9]{2,3}")
{
  version_list = make_list(
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
    '6.2(20a)',
    '6.2(22)',
    '6.2(24)',
    '6.2(24a)',
    '6.2(26)',
    '7.2(0)D1(1)',
    '7.2(1)D1(1)',
    '7.2(2)D1(2)',
    '7.2(2)D1(1)',
    '7.2(2)D1(3)',
    '7.2(2)D1(4)',
    '7.3(0)D1(1)',
    '7.3(0)DX(1)',
    '7.3(1)D1(1)',
    '7.3(2)D1(1)',
    '7.3(2)D1(2)',
    '7.3(2)D1(3)',
    '7.3(2)D1(3a)',
    '7.3(2)D1(1d)',
    '8.0(1)',
    '8.1(1)',
    '8.1(2)',
    '8.1(2a)',
    '8.2(1)',
    '8.2(2)',
    '8.2(3)',
    '8.2(4)',
    '8.2(5)',
    '8.2(6)',
    '8.2(7)',
    '8.2(7a)',
    '8.2(8)',
    '8.2(9)',
    '8.3(1)',
    '8.3(2)',
    '7.3(3)D1(1)',
    '7.3(4)D1(1)',
    '8.4(1)',
    '8.4(2)',
    '8.4(3)',
    '8.4(4)',
    '8.4(4a)',
    '8.4(5)',
    '8.4(6)',
    '8.4(6a)',
    '8.4(7)',
    '7.3(5)D1(1)',
    '7.3(6)D1(1)',
    '7.3(7)D1(1)',
    '7.3(8)D1(1)',
    '7.3(9)D1(1)'
  );
}

if ('MDS' >< product_info.device && product_info.model =~ "^9[0-9]{2,3}")
{
  version_list = make_list(
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
    '6.2(23)',
    '6.2(25)',
    '6.2(17a)',
    '6.2(27)',
    '6.2(29)',
    '6.2(31)',
    '6.2(33)',
    '7.3(0)D1(1)',
    '7.3(0)DY(1)',
    '7.3(1)D1(1)',
    '7.3(1)DY(1)',
    '8.1(1)',
    '8.1(1a)',
    '8.1(1b)',
    '8.2(1)',
    '8.2(2)',
    '8.3(1)',
    '8.3(2)',
    '9.2(1)',
    '9.2(2)',
    '9.2(1a)',
    '8.4(1)',
    '8.4(1a)',
    '8.4(2)',
    '8.4(2a)',
    '8.4(2b)',
    '8.4(2c)',
    '8.4(2d)',
    '8.4(2e)',
    '8.4(2f)',
    '9.3(1)',
    '9.3(2)',
    '8.5(1)'
  );
}

if ('Nexus' >< product_info.device && product_info.model =~ "^9[0-9]{2,3}")
{
  version_list = make_list(
    '7.0(3)F1(1)',
    '7.0(3)F2(1)',
    '7.0(3)F2(2)',
    '7.0(3)F3(1)',
    '7.0(3)F3(3)',
    '7.0(3)F3(3a)',
    '7.0(3)F3(4)',
    '7.0(3)F3(3c)',
    '7.0(3)F3(5)',
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
    '7.0(3)I2(2r)',
    '7.0(3)I2(2s)',
    '7.0(3)I2(2v)',
    '7.0(3)I2(2w)',
    '7.0(3)I2(2x)',
    '7.0(3)I2(2y)',
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
    '7.0(3)I4(1t)',
    '7.0(3)I4(6t)',
    '7.0(3)I4(9)',
    '7.0(3)I5(1)',
    '7.0(3)I5(2)',
    '7.0(3)I5(3)',
    '7.0(3)I5(3a)',
    '7.0(3)I5(3b)',
    '7.0(3)I6(1)',
    '7.0(3)I6(2)',
    '7.0(3)I7(1)',
    '7.0(3)I7(2)',
    '7.0(3)I7(3)',
    '7.0(3)I7(4)',
    '7.0(3)I7(5)',
    '7.0(3)I7(5a)',
    '7.0(3)I7(3z)',
    '7.0(3)I7(6)',
    '7.0(3)I7(7)',
    '7.0(3)I7(8)',
    '7.0(3)I7(9)',
    '7.0(3)I7(9w)',
    '7.0(3)I7(10)',
    '9.2(1)',
    '9.2(2)',
    '9.2(3)',
    '9.2(3y)',
    '9.2(4)',
    '7.0(3)IA7(1)',
    '7.0(3)IA7(2)',
    '7.0(3)IC4(4)',
    '7.0(3)IM3(1)',
    '7.0(3)IM3(2)',
    '7.0(3)IM3(2a)',
    '7.0(3)IM3(2b)',
    '7.0(3)IM3(3)',
    '9.3(1)',
    '9.3(2)',
    '9.3(3)',
    '9.3(1z)',
    '9.3(4)',
    '9.3(5)',
    '9.3(6)',
    '9.3(5w)',
    '9.3(7)',
    '9.3(7k)',
    '9.3(7a)',
    '9.3(8)',
    '9.3(9)',
    '9.3(10)',
    '9.3(11)',
    '10.1(1)',
    '10.1(2)',
    '10.2(1)',
    '10.2(1q)',
    '10.2(2)',
    '10.2(3)',
    '10.2(2a)',
    '10.2(3t)',
    '10.2(4)',
    '10.2(5)',
    '10.3(1)',
    '10.3(2)'
  );
}

if ('Nexus' >< product_info.device && product_info.model =~ "^5[0-9]{2,3}")
{
  version_list = make_list(
    '7.1(0)N1(1a)',
    '7.1(0)N1(1b)',
    '7.1(0)N1(1)',
    '7.1(1)N1(1)',
    '7.1(1)N1(1a)',
    '7.1(2)N1(1)',
    '7.1(2)N1(1a)',
    '7.1(3)N1(1)',
    '7.1(3)N1(2)',
    '7.1(3)N1(5)',
    '7.1(3)N1(4)',
    '7.1(3)N1(3)',
    '7.1(3)N1(2a)',
    '7.1(4)N1(1)',
    '7.1(4)N1(1d)',
    '7.1(4)N1(1c)',
    '7.1(4)N1(1a)',
    '7.1(5)N1(1)',
    '7.1(5)N1(1b)',
    '7.3(0)N1(1)',
    '7.3(0)N1(1b)',
    '7.3(0)N1(1a)',
    '7.3(1)N1(1)',
    '7.3(2)N1(1)',
    '7.3(2)N1(1b)',
    '7.3(2)N1(1c)',
    '7.3(3)N1(1)',
    '7.3(4)N1(1)',
    '7.3(4)N1(1a)',
    '7.3(5)N1(1)',
    '7.3(6)N1(1)',
    '7.3(6)N1(1a)',
    '7.3(7)N1(1)',
    '7.3(7)N1(1a)',
    '7.3(7)N1(1b)',
    '7.3(8)N1(1)',
    '7.3(8)N1(1a)',
    '7.3(8)N1(1b)',
    '7.3(9)N1(1)',
    '7.3(10)N1(1)',
    '7.3(11)N1(1)',
    '7.3(11)N1(1a)',
    '7.3(12)N1(1)',
    '7.3(13)N1(1)'
  );
}

if ('Nexus' >< product_info.device && product_info.model =~ "^6[0-9]{2,3}")
{
  version_list = make_list(
    '7.1(0)N1(1a)',
    '7.1(0)N1(1b)',
    '7.1(0)N1(1)',
    '7.1(1)N1(1)',
    '7.1(1)N1(1a)',
    '7.1(2)N1(1)',
    '7.1(2)N1(1a)',
    '7.1(3)N1(1)',
    '7.1(3)N1(2)',
    '7.1(3)N1(5)',
    '7.1(3)N1(4)',
    '7.1(3)N1(3)',
    '7.1(3)N1(2a)',
    '7.1(4)N1(1)',
    '7.1(4)N1(1d)',
    '7.1(4)N1(1c)',
    '7.1(4)N1(1a)',
    '7.1(5)N1(1)',
    '7.1(5)N1(1b)',
    '7.3(0)N1(1)',
    '7.3(0)N1(1b)',
    '7.3(0)N1(1a)',
    '7.3(1)N1(1)',
    '7.3(2)N1(1)',
    '7.3(2)N1(1b)',
    '7.3(2)N1(1c)',
    '7.3(3)N1(1)',
    '7.3(4)N1(1)',
    '7.3(4)N1(1a)',
    '7.3(5)N1(1)',
    '7.3(6)N1(1)',
    '7.3(6)N1(1a)',
    '7.3(7)N1(1)',
    '7.3(7)N1(1a)',
    '7.3(7)N1(1b)',
    '7.3(8)N1(1)',
    '7.3(8)N1(1a)',
    '7.3(8)N1(1b)',
    '7.3(9)N1(1)',
    '7.3(10)N1(1)',
    '7.3(11)N1(1)',
    '7.3(11)N1(1a)',
    '7.3(12)N1(1)',
    '7.3(13)N1(1)'
  );
}

var reporting = make_array(
  'port'    , 0,
  'severity', SECURITY_WARNING,
  'version' , product_info['version'],
  'bug_id'  , 'CSCwe72368, CSCwe72648, CSCwe72670, CSCwe72673, CSCwe72674'
);

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = WORKAROUND_CONFIG['tacacs_radius_directed_request'];

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
