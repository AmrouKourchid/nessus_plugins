#TRUSTED 3a42c31fbd51b72f48b1b846db7ad1d12ec9a00de4ff2a732b48b63369c73cf863aff1954ca284c00e2876deddede471c234bdc3fba35eef6cb92aaddd6945bee32fc37a10a2ae9585855f057fea2d0892d4839d2cffc094d6903ce7318b1a29b338919f1ff79ea7ab21b419d0094f25df249657e2cfc62d0a95ae69536c141e4c0841b666b9a0613368c07fd1c0c65ee63ced8802aa9283d64be6ade8aa56003bfe5da35023eb17f7fdea166b6385584e2de8984318313bbb81f87db86f97c9ab03dd0306a1265246a6d0270082c9a17506b9b059bba18c9ba2227e74467f439983162c812ae50e6b54fa664cde24c5789bc792ee7972ec80d2c075edf5fcd40c1116d18f94ba8aec42d2eb82604d34cbcf455899f9caa721dc895c7691077124e69768b87341a4d7e4be2c05388bb980ee734264030bc565951722ed9f2ad5572de331ee4b91db5653d7020d101e2add00a365ef94b62c20cf589766a969774531528ee7705905d3625263e5e3345b5630d9a510eb7d64d787d449f3d8af84cae5c71620681a89d22ec933c6236202e287fdfb676b05f4b3331f623b1c538694ef9ecf9f59a240ad58895be138252011606e07a47503647565769ef5f09c001025a6b256945febb6d840c29143be0f59b18eb1bf4239e1fb06b7c800b36c761eb400788e38edecded0c16c1ad128dfc8ff14b343ab3cf44f03200509808515
#TRUST-RSA-SHA256 ab8516a50e2cbf2aa5d1f90f964e635b9f7195fdc99d60f783d2f59da4a4ab2640c700cf2141bd51fd5a7e547fea8d4cbb6d38d9b4e9449630e584223b250a9e5181b7223eaefb7d57b3941f461743e66a8168cac2678d3c51a8917d32fbf22a21b8aece42f882c27d6425fe0ff32189dd8048550a9048ff6e26c62ea488037eb0fab05a3f91ff208ac6b3ac4ae02fbfeecb3e8cdc0621f1b3b2eab3086f7d0e64c3ce8010bf67414f2f895aab1094f93a180233b6ef8ab5587f31396a868b1e9e9f2d328fd75d1b098e048dd104f469433c929f17448b0d4bfdcdf5bd8f62355f430d14a3a80627d61c7493dbcdd6eecf6577b9e88db0cdae8c3f01204f263e93a5dbb93b59a9fdb524c792bc30ff691b0183413e9479666bd8ac35eafdd6deb825357b5a8ea58bf5c545278425620ead25b0bc0532ae6635da1c843c609e37727f2619d0bf9c46984d30a51c04321a402ea7af9ff8ddccaed1b16b143bfee120f80c4cf237c16a76d000b92df7bdfbb5e5da81b77651bc9cb87f9e7d63c01fa46b4971ae43f5416fdb105cb7fc35ee483c71b0db6859f6a34f4bc37afa04c3dc1c578733360c49468e950b32f166ca59b1cdb44c52b6b84b4b49d02baf3c7606c808097dd011154644e0d7c15f827f23b329594540a044dec28bb4c7170661c82f1558432b394f8421759d58cf2345eab313754cf26f57a7d31ca609fb30b1
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(216849);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/28");

  script_cve_id("CVE-2025-20161");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwm09739");
  script_xref(name:"CISCO-SA", value:"cisco-sa-nxos-ici-dpOjbWxk");
  script_xref(name:"IAVA", value:"2025-A-0137");

  script_name(english:"Cisco Nexus 3000 9000 Series Switches Comm Injection (cisco-sa-nxos-ici-dpOjbWxk)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco NX-OS Software is affected by a vulnerability.

  - A vulnerability in the software upgrade process of Cisco Nexus 3000 Series Switches and Cisco Nexus 9000
    Series Switches in standalone NX-OS mode could allow an authenticated, local attacker with valid
    Administrator credentials to execute a command injection attack on the underlying operating system of an
    affected device. This vulnerability is due to insufficient validation of specific elements within a
    software image. An attacker could exploit this vulnerability by installing a crafted image. A successful
    exploit could allow the attacker to execute arbitrary commands on the underlying operating system with
    root privileges. Note: Administrators should validate the hash of any software image before
    installation. (CVE-2025-20161)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nxos-ici-dpOjbWxk
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3df8e3c4");
  # https://sec.cloudapps.cisco.com/security/center/viewErp.x?alertId=ERP-75528
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6524a98e");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwm09739");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwm09739");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:M/C:P/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:L/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-20161");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(78);

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/02/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/02/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/26");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Model", "Settings/ParanoidReport", "Host/Cisco/NX-OS/Device");

  exit(0);
}

include('ccf.inc');

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

var product_info = cisco::get_product_info(name:'Cisco NX-OS Software');


if (('Nexus' >!< product_info.device || product_info.model !~ "(^|[^0-9])3[0-9]{2,3}") &&
    ('Nexus' >!< product_info.device || product_info.model !~ "(^|[^0-9])9[0-9]{2,3}"))
audit(AUDIT_HOST_NOT, 'affected');

var version_list = [];

if ('Nexus' >< product_info.device && product_info.model =~ "^3[0-9]{2,3}")
{
  version_list = make_list(
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
    '7.0(3)F3(1)',
    '7.0(3)F3(2)',
    '7.0(3)F3(3)',
    '7.0(3)F3(3a)',
    '7.0(3)F3(4)',
    '7.0(3)F3(3c)',
    '7.0(3)F3(5)',
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
    '9.3(12)',
    '9.3(13)',
    '9.3(14)',
    '10.1(1)',
    '10.1(2)',
    '10.1(2t)',
    '10.2(1)',
    '10.2(2)',
    '10.2(3)',
    '10.2(3t)',
    '10.2(4)',
    '10.2(5)',
    '10.2(3v)',
    '10.2(6)',
    '10.2(7)',
    '10.2(8)',
    '10.3(1)',
    '10.3(2)',
    '10.3(3)',
    '10.3(4a)',
    '10.3(4)',
    '10.3(5)',
    '10.3(6)',
    '10.4(1)',
    '10.4(2)',
    '10.4(3)',
    '10.5(1)'
  );
}

if ('Nexus' >< product_info.device && product_info.model =~ "^9[0-9]{2,3}")
{
  version_list = make_list(
    '7.0(3)F3(1)',
    '7.0(3)F3(3)',
    '7.0(3)F3(3a)',
    '7.0(3)F3(4)',
    '7.0(3)F3(3c)',
    '7.0(3)F3(5)',
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
    '9.3(12)',
    '9.3(13)',
    '9.3(14)',
    '10.1(1)',
    '10.1(2)',
    '10.2(1)',
    '10.2(1q)',
    '10.2(2)',
    '10.2(3)',
    '10.2(2a)',
    '10.2(4)',
    '10.2(5)',
    '10.2(6)',
    '10.2(7)',
    '10.2(8)',
    '10.3(1)',
    '10.3(2)',
    '10.3(3)',
    '10.3(99w)',
    '10.3(3w)',
    '10.3(99x)',
    '10.3(3o)',
    '10.3(4a)',
    '10.3(3p)',
    '10.3(4)',
    '10.3(3q)',
    '10.3(3x)',
    '10.3(5)',
    '10.3(4g)',
    '10.3(3r)',
    '10.3(6)',
    '10.3(4h)',
    '10.4(1)',
    '10.4(2)',
    '10.4(3)',
    '10.5(1)'
  );
}

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_WARNING,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCwm09739',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
