#TRUSTED 38693339d446e25ba239911e39950ce402f5f8b923e3c3c710ca96bd5a59c802c2a07977ee1d6445a77cafbae891c65ba3e2df117788764caf27a2f7903d0697e5ed73662e281c9f43aa605e902247721bf36c4173ea7d54b14f00bcfe68de4878946ccd3e376b48ff1ab320c4eec899fa18a648157b0011035019f0f658e6f293a453a1ad06e83a613f0c71d9864e0240451059118cbdae83cce20879cedbca25a0ebaf4935930bc757089e0ac07128a9a07edb6d5facffb33a41b2bd26463af7cc4d2e3faaf9caf01ef98b17fb1d1796ce2bf7714b87a3d909d88a16e4da4cabf46f4b129311af147f13cb032dbfbaa64fdd8aafdd830e320e434b103dec1e62d0d2cc8be2e725c9bf2ffb7bab872dfe22720a0e5ee50c9be9df6bdf6da02cf78841edf394b3b184ae0916d53bb98dbd0127c33386346e0bbdb0e7d21a42ac814efa9466e093a145078a611d402682346d00b723d5a811862ab0292227c1bc3552e4c7131c1d5d0f10cf51042aa923893825dcba62582940174bad38ad1f84daa6933bd54847b4917f49cea9a1435ec8566c724db76b2e9c8246847c5b3e0192f97077ba12414e21a33782f3e49b47efa6feff8d03e6e947c32d666ad47a792de94ed55a1b67351630534ce84b439fd82ebb93cc20be8c020dfd93bd1b3f7ec451927f78a1e291f5b8784baf199d01e29ea358d5543853dd982f11d38ee02e
#TRUST-RSA-SHA256 404b8faf5eeb19d35569a3f10724e58a80dc23960c159cae2bc321554fc1d19a4ba1266fb81aeb4b58d131b68e33b009921030f66b13b4364c37fcefad4d02782353c8f842eb62e1b77f1386c176df147961bd17d3bd2dd23b537e9b7f24b0719b9292d9269b4594a70390268827a831bb6936bad6a002c074f1f6280b220536db5aa7a54246e61868259ecc4ffdcfb4ced72a80391920e1337bbd3e01ef447a206d7156a9b183fc6eb23eb0cbedd01821a8cb06765ab3bb2918fb3ce27ddc9cc485ba9356ef615b3098589748e8503e6a1a5f53bd1cbbdf6b4aeeb0549bba3aaf92e1f5b579c6a78f21b2a498df5a959ccbfcd6cd7a7a103f4d28c95e05032b6dcebb56a0ab9602982a2bd844932e4b9d815511c6f5b15a251b2c6db54f16baf4d3438f1c8c6e1fd5a78a3ca9528247c445620c9b1f67c1ff0f1140810c880db2022b6fc781c913a2d62a995d18a98f1dc5e7734eb3294db8a7befcf091d0eaa385c494d629a2239fc0f9e1a8cead9e934804133685ce747e87e423655811e5d0eea34c74388ab3a84d1622ffd0da210fd4c665a9f42c2ce296e1643facae01229f67674811599a9b1bfd658eccc85fefe8341f458e547267f6a820efa32a4d16bfb925f6c4a7090fd994bb71c56d438fc9d13e2ead32fe84753a409e08f37a7803a222e72ace4bc083786747db1d2a10d7aa0907506c49a3a06873676a7aec
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(206348);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/27");

  script_cve_id("CVE-2024-20446");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvz72834");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwk27906");
  script_xref(name:"CISCO-SA", value:"cisco-sa-nxos-dhcp6-relay-dos-znEAA6xn");
  script_xref(name:"IAVA", value:"2024-A-0529-S");

  script_name(english:"Cisco NX-OS Software DHCPv6 Relay Agent DoS (cisco-sa-nxos-dhcp6-relay-dos-znEAA6xn)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the DHCPv6 relay agent of Cisco NX-OS Software could allow an unauthenticated, remote attacker to
cause a denial of service (DoS) condition on an affected device. This vulnerability is due to improper handling of
specific fields in a DHCPv6 RELAY-REPLY message. An attacker could exploit this vulnerability by sending a crafted
DHCPv6 packet to any IPv6 address that is configured on an affected device. A successful exploit could allow the
attacker to cause the dhcp_snoop process to crash and restart multiple times, causing the affected device to reload
and resulting in a DoS condition.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nxos-dhcp6-relay-dos-znEAA6xn
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cb4d94f6");
  # https://sec.cloudapps.cisco.com/security/center/viewErp.x?alertId=ERP-75417
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0fd3f483");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvz72834");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwk27906");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvz72834, CSCwk27906");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20446");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(476);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/08/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/30");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Model", "Host/Cisco/NX-OS/Device");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco NX-OS Software');

var version_list = [];

if ('Nexus' >!< product_info.device) audit(AUDIT_DEVICE_NOT_VULN, product_info.device);

if (product_info.model =~ "^7[0-9]{3}")
{
  version_list = make_list(
    '8.2(11)'
  );
}
else if (product_info.model =~ "^3[0-9]{3}")
{
  version_list = make_list(
    '9.3(9)',
    '10.2(1)'
  );
}
else if (product_info.model =~ "^9[0-9]{3}")
{
  version_list = make_list(
    '9.3(9)',
    '10.2(1)',
    '10.2(1q)'
  );
}
else audit(AUDIT_HOST_NOT, 'affected');

var reporting = make_array(
  'port'    , 0,
  'severity', SECURITY_HOLE,
  'version' , product_info['version'],
  'bug_id'  , 'CSCvz72834, CSCwk27906'
);

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround'], CISCO_WORKAROUNDS['ios_xr_ipv6']);
var workaround_params = WORKAROUND_CONFIG['dhcpv6_relay'];

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  require_all_workarounds:TRUE,
  reporting:reporting,
  vuln_versions:version_list
);
