#TRUSTED 028cc20fa5ba1418d0f46e8f248b6e5d083a01c73dc66d1bbc348d676983e7d07df2800ed4d9db518d4b28e0a3561a2ecd7a91d0a71a20c0e531098971b944d8f9d4f99f17aa2df1d56362998edd56461112c897f724d934dd4cf40300cf4e73b129898806eaa0f60913ba215330305b6122553f4721da453bbc020168123fbe382adc624cc0dfea4f53372b18e40501e7ae97092cbb92a817710cad22f4151510cf7b908e157b5bbb45245e76c5f808a96db0350eb812fb6e87b7c8ef40451017f8b060fbc0e95ea46a351c52dee86f2c22b8f97cc370967971799aaa9ab332ec4b73598e2e963e481761052b48f20e42ab1976b1f03625bf05f3438b25b91fdb67404955dfe1728b16719885bb4ee515670183afc9e6fee2011067e48b2cd64389167d890fd44f5522779063a5f755aa404b30394db912d8e22cfea605cd7161238a30bcb9befb117a34b1f5e5bd275e963c7488425f9c5c40b6cfbdf1743e5c72595be352fa661bfa1b4bd262efb8c26868fa6f49661a291745027ee48afc2c193a597aa42839615a00c5ad3d859ecd38161d58ec8934aa4ea66ae701c066731dd0cb7cd909bd0deb81430c48faaa785885fe03e4b502cf93a792c249c5b8762ece65af566c71d2f967b7973d9afc4929bf554d1a47bbbb49731616cc2b65cf13562bd86e067e9d6ab68acaf3ecc4b59efeceae1c8474c9a467657e5534ed
#TRUST-RSA-SHA256 4c3a0dbed32e37a691e306a08bad19e1e9ad1c33ac54dbc56712635f12b4a38016cf36bbae3bcb7e3e336aee4a787791a8c85d675e24d07abc69f1eb539b730eac2524ba33910b3ad976abb9cc3ed3f18b6290caa7f813e0a181a1f38bf10e96cb737c8a2efa41273583cf6c460cc72160a3d022482e786886c10f76f3132afe57fa9fe5074c94342092d35d316c082abb95b21c02b926f568ccda23ecd83cc9815566349d96b4a2ee6f0a488b0d2e7096ebd85117cdafc3398d6aabc0b61691da6570c0d99f06f6d73f99495b0b49547b167daf235f2881a5f74c3fb3c537a2561733f63108627cea690af5f72e054e4ad8446299f05f649f50755efa065055d72131fea28eef88f2093d044cd59940d014ae005c7aec51127debb5ff5ceb64ca8fdda0255a615423fbb0fdd68e2f664e6b7f054cbe0e961086b2e382809e8067c2561a72776dbb8e0ed111ef97af2cc1c857a76024b503fed0fdb65b125d658abcd705f322a0e8387428518101ec22d58df02615d1d1da75b838d40a47f647aa3c367b22e96e5f9bfa77c05969193440cce8099953d8ad45fd37937dc84e628dd6167270341c6c980336727b7c97bf34b22cb7486b4ce7af2eaded9921ae16a802c66c085e1da71b96333a65d4b192886924c0def2a6f5551f19a218b9b5f9ae2e2399c7b78fd90ce5e129a332755ba8c8641da703b664d8770c38d27b0f8e
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(213518);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/07");

  script_cve_id("CVE-2024-20455");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwi07137");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sdwan-utd-dos-hDATqxs");
  script_xref(name:"IAVA", value:"2024-A-0592");

  script_name(english:"Cisco Catalyst SD-WAN Routers DoS (cisco-sa-sdwan-utd-dos-hDATqxs)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a vulnerability.

  - A vulnerability in the process that classifies traffic that is going to the Unified Threat Defense (UTD)
    component of Cisco IOS XE Software in controller mode could allow an unauthenticated, remote attacker to
    cause a denial of service (DoS) condition on an affected device. This vulnerability exists because UTD
    improperly handles certain packets as those packets egress an SD-WAN IPsec tunnel. An attacker could
    exploit this vulnerability by sending crafted traffic through an SD-WAN IPsec tunnel that is configured on
    an affected device. A successful exploit could allow the attacker to cause the device to reload, resulting
    in a DoS condition. Note: SD-WAN tunnels that are configured with Generic Routing Encapsulation (GRE) are
    not affected by this vulnerability. (CVE-2024-20455)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-utd-dos-hDATqxs
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5ca1c989");
  # https://sec.cloudapps.cisco.com/security/center/viewErp.x?alertId=ERP-75169
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e0341eea");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwi07137");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwi07137");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20455");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(371);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/07");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/IOS-XE/Model", "Host/Cisco/SDWAN");

  exit(0);
}
include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XE Software');
var model = product_info['model'];
var device_model = get_kb_item_or_exit('Host/Cisco/device_model');

if ('cat' >!< tolower(device_model) || model !~ '8[0235][0-9][0-9]'){
  if ('series integrated services' >!< tolower(device_model))
  {
    audit(AUDIT_HOST_NOT, 'affected');
  }
}

var version_list=make_list(
  '17.1.1',
  '17.1.1a',
  '17.1.1s',
  '17.1.1t',
  '17.1.2',
  '17.1.3',
  '17.2.1',
  '17.2.1a',
  '17.2.1r',
  '17.2.1v',
  '17.2.2',
  '17.2.3',
  '17.3.1',
  '17.3.1a',
  '17.3.1w',
  '17.3.1x',
  '17.3.1z',
  '17.3.2',
  '17.3.2a',
  '17.3.3',
  '17.3.3a',
  '17.3.4',
  '17.3.4a',
  '17.3.4b',
  '17.3.4c',
  '17.3.5',
  '17.3.5a',
  '17.3.5b',
  '17.3.6',
  '17.3.7',
  '17.3.8',
  '17.3.8a',
  '17.4.1',
  '17.4.1a',
  '17.4.1b',
  '17.4.1c',
  '17.4.2',
  '17.4.2a',
  '17.5.1',
  '17.5.1a',
  '17.5.1b',
  '17.5.1c',
  '17.6.1',
  '17.6.1a',
  '17.6.1w',
  '17.6.1x',
  '17.6.1y',
  '17.6.1z',
  '17.6.1z1',
  '17.6.2',
  '17.6.3',
  '17.6.3a',
  '17.6.4',
  '17.6.4',
  '17.6.5',
  '17.6.5a',
  '17.6.6',
  '17.6.6a',
  '17.7.1',
  '17.7.1a',
  '17.7.1b',
  '17.7.2',
  '17.8.1',
  '17.8.1a',
  '17.9.1',
  '17.9.1a',
  '17.9.1w',
  '17.9.1x',
  '17.9.1x1',
  '17.9.1y',
  '17.9.1y1',
  '17.9.2',
  '17.9.2a',
  '17.9.3',
  '17.9.3a',
  '17.9.4',
  '17.9.4a',
  '17.9.5',
  '17.9.5a',
  '17.9.5b',
  '17.9.5c',
  '17.9.5d',
  '17.10.1',
  '17.10.1a',
  '17.10.1b',
  '17.11.1',
  '17.11.1a',
  '17.11.99SW',
  '17.12.1',
  '17.12.1a',
  '17.12.1w',
  '17.12.1z2',
  '17.12.2',
  '17.12.2a',
  '17.13.1',
  '17.13.1a'
);

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = [
  WORKAROUND_CONFIG['show_sdwan_bfd_sessions'],
  WORKAROUND_CONFIG['show_platform_software_device-mode'],
  WORKAROUND_CONFIG['utd_enabled'],
  {'require_all_generic_workarounds':TRUE}
];

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_HOLE,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCwi07137',
  'disable_caveat', TRUE,
  'cmds'          , make_list('show sdwan bfd sessions | include ipsec', 
                              'show platform software device-mode', 
                              'show utd engine standard status')
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list,
  workarounds: workarounds,
  workaround_params:workaround_params
);
