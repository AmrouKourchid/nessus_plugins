#TRUSTED 2c4007a9f0a447624d2c2c2c9500f3d79f21d6d92dbd45298d8115d43ff52e703db52681c3d4d6cc2a991fbb3965087776487b779ebe901c7768f3f4669420e76b7ca02cf870b714d38eed20a1f955c76bd726f9cb8032e61d2d7310ebc8d154abb9ca6876e26e12d20d12932b200027057d2c8e0e1c0bd0c0e15f009aed3302a53f5c1f5054526033096ca1129558b5f23f67d000d925458c8301465f8ba1c44ce59ada22df36dda4232e4bdeb48fdf3e1d367d1971e103d0ff115acc6ef986fccf50923b58057cc530fb1e870bd62c42f7f7c41e61274712495471ef832e1f0884912b661eb4a3e8494b18fa4d2b00ceac63303adba637e56e811f1f9410b9089db35b5f702389446a3e98718846a06bc4b4fe5b6dc4cb2545bb2b9d478a593cc07bd6ba937a3d99f472bd6bd672742a57ed295fbcab63865572ab54b813e6b50052acc409fd06cf8928444f92af7cb0f655b06e7ce4b662ddb2737222d6edaab2c99d9ce9411bd1b26102d9ce14eb3a79f3de09dc9cb479ab980dfeb10469054832080485189699093e91b1dbb577f9edaeee730df159f12e5f026eae1dea915226724ea3e111cfa211d1e8bce7fcb561d7b86e5e9c377b4e61156f98aadac20b2a1ab23d7186ac24c2de4dbab9e0b567bad33a84eda53abb8d54916ee103fef1f367464964e82432a39f36bd57f9c4dbdf4e60384e225892a79094ac0c17
#TRUST-RSA-SHA256 a74f069371b61d6465b2c0f8931f956129f6d08786071b84006ff43425fcba132b44b57d88187b6139f07599f831843e093bb4f3975a11564cc3f08e5639b757f89dbe040010df355391384f2308e73a8c553b6508a8e4cf8f4d35b7885600e2e9c5a72dabc1a5ff347dd86375de56bd0921043cfa9d0e573208f040d5a3c1c49ed4e3d2089f3515e386e04ad62de40b4d1e45a21a26408d878ca58001e46a95b1f38cd703fbac2e4c563f11b45cd7ada1efcf12818d4b06a06d5a440bcc2da6d88942f07eba68c20a948b0f4cafd58ab897d259af4d421c68d51f3e0744d8cfff25500b526c93e8c479d84b8d3325ba2ee3ae14b653e8f1758e8b1d8b348840c4486f52875c40f72d2edf9d9a71d10a66307beb9d9b0c3d27cc13c8fe944d174444b26a1e4c8ee77f972f5a853d2aa8ccc015427c6a3bc18707165bdb2f564de43ecf1f55fb8508f77c9d332a36d91a5a81f2b68f8a1d8cb0f2e75ce40774c32ff6c9ed834006b35cae2c467ed794538afa3cf8decc2c1c0762ced28aab5a7c73a9f5f966d82124cd6853bae7a67dbe4973ec7d2f81541c902602d832134c6e1f5d5863e1a664101ed911ce7b3213026e5199de1495ca05179f64bb5286cc4ba32cd6e188bf769128722f3d66ec426ee1c0ff445cb6117fe2d48d9650b868d7004f56a0a080a2bfedb0a47aa94b9268e4d5250e69d1ab79330118a35c279b96
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(216942);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/28");

  script_cve_id("CVE-2025-20111");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwj98161");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwk41797");
  script_xref(name:"CISCO-SA", value:"cisco-sa-n3kn9k-healthdos-eOqSWK4g");
  script_xref(name:"IAVA", value:"2025-A-0137");

  script_name(english:"Cisco Nexus 3000 9000 Series Switches Health Monitoring Diagnostics DoS (cisco-sa-n3kn9k-healthdos-eOqSWK4g)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco NX-OS Software is affected by a vulnerability.

  - A vulnerability in the health monitoring diagnostics of Cisco Nexus 3000 Series Switches and Cisco Nexus
    9000 Series Switches in standalone NX-OS mode could allow an unauthenticated, adjacent attacker to cause
    the device to reload unexpectedly, resulting in a denial of service (DoS) condition. This vulnerability is
    due to the incorrect handling of specific Ethernet frames. An attacker could exploit this vulnerability by
    sending a sustained rate of crafted Ethernet frames to an affected device. A successful exploit could
    allow the attacker to cause the device to reload. (CVE-2025-20111)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-n3kn9k-healthdos-eOqSWK4g
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fb3fe0df");
  # https://sec.cloudapps.cisco.com/security/center/viewErp.x?alertId=ERP-75528
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6524a98e");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwj98161");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwk41797");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCwj98161, CSCwk41797");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-20111");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(1220);

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/02/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/02/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/28");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Settings/ParanoidReport", "Host/Cisco/NX-OS/Model", "Host/Cisco/NX-OS/Device");

  exit(0);
}

include('cisco_workarounds.inc');
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
    '10.4(1)',
    '10.4(2)',
    '10.4(3)',
    '10.5(1)'
  );
}

if ('Nexus' >< product_info.device && product_info.model =~ "^9[0-9]{2,3}")
{
  version_list = make_list(
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
    '10.3(4h)',
    '10.4(1)',
    '10.4(2)',
    '10.4(3)',
    '10.5(1)'
  );
}

var reporting = make_array(
  'port'    , 0,
  'severity', SECURITY_WARNING,
  'version' , product_info['version'],
  'bug_id'  , 'CSCwj98161, CSCwk41797'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
