#TRUSTED 7d1c975642680c76dd6525f88185a5bc5542966ea90e71bf6c8ff77ccb002db9c4e898ca8d649f9736d486a7fccfc24accd65568bf6cdf7e90154b6c79ee2b5b6bdfc93d65c2edbd470aae8735e115b8d81bcb3d9e8b32323a77926074c343f20be967df84cf94b782d2c4c2c3ed3059feac4cf944211e0ab52e6216b382ecb7ad11e474a4d2ca8671a9d572d14dca2c3facf3ff040b90faefdfe2d38e7b49faec47523a79844ebca5ded4eb2d5ccb151658810f5b35af8d6e806c4fd76a8bcdba64ac491a4afce54200bd55cb1c17925dd80fce2dc6093edb429048a1e31096a90f48eb360e0ca2c2090c7355edd3158252997ad4862074f00570da0d8121ef213fe7c1a100f72e721f86ced70bd32cb225a4acabecc6771820d7307f448d4c4154cfc835bcbf9de940a2f9b7dc726769198bf4ef8a8e5064528132dad6d614d038e53ce086a2892fb99c1b4cd1032676aae2416a2cb96350f17cb2fe25498d9b2e11e78eefdf3305367036240c6ee6856bae7f1ce966cd5396cc051a82a8a4ae696c90decb06e8918523ef76ef72e1381f5b305de7653db6160f49239673bad8be0403fdc271cfa2740413cdb05b99c97f74a07f0421994b4b087bc13f5b5e7c7e762ffb3a9a83cab53584043899509c126d572242aa9eda1a025a429cbbd49b635d193246c61d6f31946b4278c81fa8d9e75f9611e32c2b6cd7c81b7a6a41
#TRUST-RSA-SHA256 35089f4cde585fb2a5f7e0f778dbd89b6574445129616b9ee4d44d9849fd335ece41e45b0c9e07ed9720069a7ad72279e176b042669952abf72b3385109e82c4171070619f3c2dfded174cb13d12f00af842efac0bc602ecdc5b5d53c960ac690b56e186664efb73c3c1921d3f3a182981863aad4ee849675c5ffe4f0468aa6a6b618b149505c8403a1a0c0368bf8ab0a6b044dedd3e8987a7bf5a3f5bc6b672953bd8883d3170cd5d4742bc47a7622ea5f2397dc5349663689954c279fd70c581465ba77555df68734846f11a6bc321f9a93be2ab8513a79cc562afa15d470db4be9dc28cccf46d0c2b3234b9f6f9bc75f2c47ad463d4f9ed1264493b71895276c167e1f232a26bfbf47ce04aef11b708ed5122ba4e7e87f05d9d14b4ebf779b99cc2c1ddfb6557a25e2d185b233936ed752a3e1ca7fef237f04f2bc987045483c67151b4aaad7a69006512504992969dfeac1934233b1636bb2dbe656bbb681516a46925df6ba99eaf3bb706f005b276e2a45be28082af13f34eea4dc0d27db101823c32cf99e7d2df6bcceac54d942cdbb30d412173136e4f9bfa91ba89bfa9a8d6128055d4936febf8d57cf356345d39153c55665180700e472e79f071b905722ae7e7c9c9572da13c7af51f66061e6340954911b0d17d32b85c3b4855a9d7111b2a62b7d7e75fc2a314876aef1da99389e8b6ca2ae1a67536b535144b4b
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(132246);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/03");

  script_cve_id("CVE-2019-1602");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvk70659");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190306-nxos-escalation");

  script_name(english:"Cisco NX-OS Software Privilege Escalation Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco NX-OS Software is
affected by following vulnerability

  - A vulnerability in the filesystem permissions of Cisco
    NX-OS Software could allow an authenticated, local
    attacker to access sensitive data that could be used to
    elevate their privileges to administrator.The
    vulnerability is due to improper implementation of
    filesystem permissions. An attacker could exploit this
    vulnerability by logging in to the CLI of an affected
    device, accessing a specific file, and leveraging this
    information to authenticate to the NX-API server. A
    successful exploit could allow an attacker to make
    configuration changes as administrator.Note: NX-API is
    disabled by default. (CVE-2019-1602)

Please see the included Cisco BIDs and Cisco Security Advisory for
more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190306-nxos-escalation
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1f435018");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-70757");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvk70659");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvk70659");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1602");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(264);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/18");

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
if (product_info.device == 'Nexus' && product_info.model =~ '^3[05][0-9][0-9]')
  cbi = 'CSCvj59009';
else if (product_info.device == 'Nexus' && product_info.model =~ '^(95|36)[0-9][0-9]')
  cbi = 'CSCvk70659';
else if (product_info.device == 'Nexus' && product_info.model =~ '^(90)[0-9][0-9]')
  cbi = 'CSCvj59009';
else audit(AUDIT_HOST_NOT, 'affected');

version_list=make_list(
  '7.0(3)I7(3)',
  '7.0(3)I7(2)',
  '7.0(3)I7(1)',
  '7.0(3)I6(2)',
  '7.0(3)I6(1)',
  '7.0(3)I5(2)',
  '7.0(3)I5(1)',
  '7.0(3)F3(4)',
  '7.0(3)F3(3a)',
  '7.0(3)F3(3)',
  '7.0(3)F3(2)',
  '7.0(3)F3(1)'
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
