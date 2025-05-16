#TRUSTED afecd83dfe91361a2767f24ce60ceaa8ea4fb1cf6db5c54fcd79bc247deb7292eabaabc7db8ea038045098dd03ea24e6e2255401abfd733a5e638f0b9cb38171e1c9b3b3685b7796216b1220d312dae4b3a3f24075abfdbb1325fab706c05c8f118e60c90c5a9db34daf9d5564495f1a18dc7ddb5242749bbdb9244f22e67cc2e078d8b4987d62edf6b0d5fd415353eb5fb7991177808731994f013017bad38cb5f77d1dbda3658511c55d174f1219c99cb6611266856f648a02cf721260e0829f7fe9c04f98e689bb0c3e471cfdcf7370c9c6c451b93160cf7d75261f92e3b3144b7855c316d75378b0ee14e1a504ca129611c94f7f8473dd7ef1b6e4f56ffd184f4f95c51e2c769f88c61aa8edf09f938cf5192c7c828faab49898cd83abf8416a8c48ff72db99ce94529b173f83cfcb7249c077eb973c6fca5794c470fb247c4ee168b3c727f3becca9915d662ec9673de0732da011b88f89d8e50a0da922aa76ead1fccfa9f16062c8893f690417bc5bae3c9b18da315ea4722a4d7039cedc9087661cd076432dccc87d64d9f37ef421961b3f6bb819c848a7669b49d047cf6100145689fda8d7f63927cda2124465266520d6cb8a4478d70505aa5368fa5df8270740d22c97317a1a8e0852e62df45df194767565afa87cf2271524ba36700f56936d749193b9c5155cd81a646b276b1fa8831f617514b16e37b5b52ae3
#TRUST-RSA-SHA256 662e4ee3963fdc14f3e3b0bfcbba54d11b3c302dadc9ad13e6e92a05a8d7a1e623d905d44bc79aaab4859a705640b70a5de4683b589d61829fd762f2c055e3445c39c7b6428243f2240332aea31eee6952dbd5c7e3b93f937134488487cedae29669c6f254f65f6cf9b246d1eba22a778bcde02d4d2ee919f33a44241d7c348ec3a7f9e4f6ffb256621ab3eefe6b48a0199e014af3861afe2f6d9bea744d2b09e3378f0ea4b5b41360612a3174e25735dea7b258833760ac9f29c3b7b1d7820ab3c4273f808aac3c4ced1d3f71659a82d616fb9ebe1941edad4b09dcb0cf199b13ba747b0a6641fa8c5515d3f0ed3483cd767c19cd6b214018645084187c31a6fc7df567319e157b17a0599236f1ac8adf8fbbc8a950931d8ce11ed913bd259865f2c698ef5ad6d42d9a8aadaaecd009fb9f0e42a8fb09d6f3318849d9cb4fcddd00335c6f6202a8ee9670698ac18d54504652ab2f46f294381a84576d3bdf6e4392f3417041ac097f3753c1f5d17ec75af5b85fd5db758764e1515cbd5e0b8f93aa82eea5e118f054417842fc5253f851a04b9183b74ea2ecfdf5777dface1e32bd5bc1ba3a41457c125f707b4a75bff6d687e0032b4bf68c5b7251341160fc9e48635b1d4d23ddb2724b4bbfc52625e66805780d688a0deb1af3dca281fa612d478050f19e596e053bf54408cace6c859a814362dab6afd46ad073a94041d5
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(180171);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/25");

  script_cve_id("CVE-2023-20169");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe11136");
  script_xref(name:"CISCO-SA", value:"cisco-sa-nxos-n3_9k-isis-dos-FTCXB4Vb");
  script_xref(name:"IAVA", value:"2023-A-0439");

  script_name(english:"Cisco Nexus 3000 9000 Series Switches IS-IS Protocol DoS (cisco-sa-nxos-n3_9k-isis-dos-FTCXB4Vb)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the Intermediate System-to-Intermediate System (IS-IS) protocol of Cisco NX-OS Software for the 
Cisco Nexus 3000 Series Switches and Cisco Nexus 9000 Series Switches in standalone NX-OS mode could allow an 
unauthenticated, adjacent attacker to cause the IS-IS process to unexpectedly restart, which could cause an affected 
device to reload. This vulnerability is due to insufficient input validation when parsing an ingress IS-IS packet. An 
attacker could exploit this vulnerability by sending a crafted IS-IS packet to an affected device. A successful exploit 
could allow the attacker to cause a denial of service (DoS) condition due to the unexpected restart of the IS-IS 
process, which could cause the affected device to reload. Note: The IS-IS protocol is a routing protocol. To exploit 
this vulnerability, an attacker must be Layer 2 adjacent to the affected device.

Please see the included Cisco BID and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nxos-n3_9k-isis-dos-FTCXB4Vb
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0b3ab73d");
  # https://sec.cloudapps.cisco.com/security/center/viewErp.x?alertId=ERP-75058
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d5b1feb9");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwe11136");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwe11136");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20169");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/08/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/08/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/08/24");

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

if ('Nexus' >!< product_info.device || product_info.model !~ "^[39][0-9]{3}$")
  audit(AUDIT_HOST_NOT, 'an affected model');

var version_list = make_list( '10.3(2)');

var reporting = make_array(
  'port'    , 0,
  'severity', SECURITY_WARNING,
  'version' , product_info['version'],
  'bug_id'  , 'CSCwe11136',
  'cmds'    , make_list('show running-config')
);

var workarounds = make_list(CISCO_WORKAROUNDS['isis']);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  reporting:reporting,
  vuln_versions:version_list
);
