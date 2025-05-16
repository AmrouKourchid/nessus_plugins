#TRUSTED 12f93f58ffb7eabcfcb441a231375234904f381845e70a21214bff4f22b644e4c16ee6f05aaeb773212721b90cb7ec9819ecaa34c3e1d362e6585cdb56cb6c67bfe1a601ace8c65837f0cf59d9b85bdc9fc7ac43fa73c4fd267e65a3006b88adf5437e800acd1dd87d782d33d5cc51bb3759a47102e67e1cefaa840610c566d0e4ebecf12431c1b90b97cec7b37e0fca93f002ca0f9374685b6f27af38f7d0dfb2118c83220c9579e1ece212ba0b270dfd76e513fb98b0e481bafc4727cbf754b298d0d8abf3f091e826907a72d22102289faac1dbefcebf6e18a2da8fd12eb789dc46484ae603b6baff66c1a43127875bb208ba0f2b50a392be198a7b24d5b319f287db2e9af8ddc52e47494a1c0e253a72ff82a9a095d6d5ef629a9c4ddcd48919a620b9d789203fce376030f8d0a2531af5cab5619eaad32318e785b8e33b92f57af06d86fab04e4b4aa0d5f4aeae249f14d2ca680d1634bab978e2bbd62a4af675261b9e5e9373a9d997f6d60f9fd37d95a2a27e0114e029964621d9330de7e3ed9fcb7e8050e69b46bdc0f18aee063aa400b6e4bbd331c717162795810d56abdb70393c58b3b1667f1b147bccb54ba1b9ebd88fe1573c1fc5e97ff51f3f70b647d3c0680b247a1dd1b1241ae897c898eb2673a706f3c5b404d86921485d6017f7d761c2b81877dea9500617f102d339b4350333240c0bc2d032d468b837
#TRUST-RSA-SHA256 9b6541fd6ab57b0ca7ed810dfbd96eb85e7423eeff6dd95ab0c4ab9c0fdad4e4a6eb9fbb2998c88853f35221c76adc22d91166eaec4a2f58ea2ca7f1e0dda031406cb21b790f0915e09508f6f9b0ee9151c79970074c4ab70ebe67cfa9a93b5e4d072d5ec978456e91ad6a2a32ff820aab09debf4eb7c3821d2b42270d25e55713f8d209968ca824a056e7be169b1faea09c75d35dd396036dda5d8b31448984d07d422482dfc858009732da233f83d9f1bc303e7d2407356f1e193eccddbc2b4560c9434e868927ae7d021b719acc7d7f88cac80e6d57eb85fdf5fb5079739c8d7c1b7453d290fe168b5a96dc863ba5f2fab4ffe5cb58cf7e79ff66335db30166a9684b92be0d57ad0b1d82c73a6e3186d2e4d82e6104b12db2f9e9b0e3f119ec6cd31eb1db9b90b6cee655a0d972666de4c1b21abf62d27d9c4be107f5c235e46e34cba4066cc36ef3dfab041b65d767163a5284781f2b261122ee454c98fabb55427db9c049c2087131edbe1944261fea93d1e5836ead8af39359436787a9d9a7b6305fb7dd214e58d15ee99a309f6d900001efbd3dabe4f3d5df38b11a89f16700b2c4355a66634e1942c03d8b66749015a340abe79bce2bdcf2d9f752e7da1e5531c2b5939916d2c4107e30928fb36c313a611b8ec5846d56bd38d56d9e0c31f6efff40dfe1731913bf9e9f668e757bbc03cc7068551310d5eeddc9de09
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(129732);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2019-12653");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvj91021");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190925-rawtcp-dos");

  script_name(english:"Cisco IOS XE Software Raw Socket Transport Denial of Service Vulnerability");
  script_summary(english:"Checks the version of Cisco IOS XE Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a vulnerability. The vulnerability in
the Raw Socket Transport feature of Cisco IOS XE Software could allow an unauthenticated, remote attacker to trigger
a reload of an affected device, resulting in a denial of service (DoS) condition. The vulnerability is due to improper
parsing of Raw Socket Transport payloads. An attacker could exploit this vulnerability by establishing a TCP session
and then sending a malicious TCP segment via IPv4 to an affected device. This cannot be exploited via IPv6, as the Raw
Socket Transport feature does not support IPv6 as a network layer protocol. 

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190925-rawtcp-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0cd2a48a");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-72547");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj91021");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvj91021");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12653");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/09");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

model = toupper(product_info['model']);
if (model !~ 'ASR90[0-9]([^0-9]|$)')
  audit(AUDIT_HOST_NOT, 'an affected model');

version_list=make_list(
  '3.2.0JA',
  '16.9.4',
  '16.9.3s',
  '16.9.3h',
  '16.9.3a',
  '16.9.3',
  '16.9.2s',
  '16.9.2a',
  '16.9.2',
  '16.9.1s',
  '16.9.1d',
  '16.9.1c',
  '16.9.1b',
  '16.9.1a',
  '16.9.1'
);

workarounds = make_list(CISCO_WORKAROUNDS['raw_socket_tcp_iosxe']);
workaround_params = make_list();

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvj91021',
  'cmds'     , make_list('show raw-socket tcp detail | include Socket|listening')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list,
  router_only: TRUE
);
