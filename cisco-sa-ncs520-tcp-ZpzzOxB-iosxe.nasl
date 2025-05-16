#TRUSTED 65448cc2e32f19273939e4a33fbf7b3e3e94cc3b0e24dbb8b5c940f1c13cf3dc2f71a88553ce7ad152d460898dc423543b16647cda24bdbcca50222e5cd81917afa9f2ffc9a286406d5065c9bd17ac61c5c81d592786dafb37e6de73b363e5266e6194a1639c1c1b1efd33262b34b66e6759c098a082d112e6757208bf1738ef3d3d32953b8a0a9b84463fa04b908c2e46a4b41e170f3ef62aabf0fc3fd2c3db0ebf9b72059113ee14f17f3b7e08427e5fbffbe4ae8d2c478fdb27b4ac61e5c33c39b5242f4f5cd825c4aa7821ce967051244b85872b518f1e2eae14da9da821f91bff33ebcabe66b406365174304a5079d66ad24f8bc5c411616e00e0e764fec7621911c10a93855875e2ba5b73c5e1ecc3c976101cdc841c34c8211213ff0bcfa6ee6e4e93917b074d3269e267c9d3c868dc7ae46f70a2c6d8e67c648e059b2baa95e1f26c7d05eabfc95a91763a20ee72dd96b8304f3328a3eb324336a6ad4e28159920c90a2d9e8f1eaa9d8b8ebafba073136c2b48b80408960c16e677ec7e1cc1de491a5d9c4d13a98cfef506e2896df2fd67454db1f7292973e35e6b28bc9e3220b2fc36826684c3f6a08f0a168a11af08c0fcac829be4839ca66e506aff49c886f76aaf861f1d55582b60f560730b19224c3d56da868683bce90cb136512a6ef7643bf2f6f052f314f0ccf6313427b6a71ecbc732f7e1b40eeab84ace
#TRUST-RSA-SHA256 abc3673a44307ed62c2a1c18b7f6f90254798c5f094905f5e087141cd613a68fa1ae3ab043f7b59b48ae8abd0a9dad1d7f9c26ec99bde462929a3589f54ba810ca9f601156e26656e419fe245bcbca11c0e5a7d8b3e84bc453322d6488c0a5234307e3ee2f59f2ec1a21c813df04d574d1b94634de85be2d4191dc735631e852f425edb67890acad8f7965a90c096a139ac403c3e8d7a542b3388306417c49757dbc486f4ac396b9349406f5bd77061dde446ee087de8c25309c94b1b9d134a769fac5280d9604b7ef9283d85aa1fd182c98dc5b01e2d91ed58a87881fbf1faf5718259f75c3c37c9405d5f444ee480f35a13c142476ba326d1be51f8b19b8cc3371bc72b9c49d0376f632158d40d76aaad0c5de97b8a00703ed64324db3d5e1966e90688d9f48d9eaa0b413bcec50e7ddc633e55647682bb145e5ed872bf5068e5fc741d5ed5e8406844a95aae45715d5f5da535655fd79cea3b30dbd49b57bf59b22c6c120e8a887d7ac974f81bda8812dedf6a1ff71bcd429a7602538de16ba825f2e54f2bcaeccc7e7bb483b8c12fcdea68dbc270065556c3a7f68d2d6df939aa575218653fc8cfe5879be3b5322899175165142c8ffd82fd6130a5753e4152b54e2aa0cdf08b2bda5f2b8bff2f2c38bff9da469767cf5a87b4ec24b428e1357dedf7645421e4aa02651d9cece467d2a040f3ff1d57eb0121879491ca3d4
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148098);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2021-1394");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvm96192");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ncs520-tcp-ZpzzOxB");

  script_name(english:"Cisco IOS XE Software for Network Convergence System 520 Routers Denial of Service (cisco-sa-ncs520-tcp-ZpzzOxB)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS-XE Software is affected by a vulnerability. Please see the included
Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ncs520-tcp-ZpzzOxB
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?42f2c43b");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvm96192");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvm96192");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1394");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/24");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list=make_list(
  '16.10.1',
  '16.10.1a',
  '16.10.1b',
  '16.10.1c',
  '16.10.1d',
  '16.10.1e',
  '16.10.1f',
  '16.10.1g',
  '16.10.1s',
  '17.2.1v'
);

workarounds = make_list(
  CISCO_WORKAROUNDS['HTTP_Server_iosxe']
);

workaround_params = {'no_active_sessions' : 1};

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'bug_id'   , 'CSCvm96192',
  'cmds'     , make_list('show running-config'),
  'version'  , product_info['version']
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
