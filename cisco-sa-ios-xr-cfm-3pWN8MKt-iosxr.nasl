#TRUSTED 317ef4cd4f6061bd15eab1b5fa6270b6e748a1437a4d8e611b4bd6a016fd27fbc267a03f9c61606126860a97ddb4c83ba069cd80ae7aab0a53765edbffa5ad213a444dbc5f765330c2e1ae5d6512c149e33b076af19d87a89cb7e79bb6d6ef0b33c5cabd83d3a98d0f6dce2f135f1042a7bbab0810282b496cbd1994edb05a9e403b22b54d9c3769d8f69b8f6ea781be8f568ba1077ab3b2a1301df93b4481b0bbaab182e87b5f615c2e04d12c13fe1e2012dc522ac4362deb9cb2e9ee67c3598a7abb276f9031c6e6b98320f792c2e773699120a238f5703972054b8edfe745af902ae3e3d6905ab3b319c2a1c1130b7b1d2272ce314f3166437139cebd5c878b97a28560fdc2ad2be6ceaa9644e2adc2fa91802c0cebecf8ecac1d8ea02d60b30e29d544fabb759560ff3e17974ae229a1fa58357e41583dfed886ff204911e67070c96b8c12df1565a105076f0dcf9ca21e6593f865236d652576703997fe363c73927b6d878b3b2b7f52f9dfb8ece20c061a2dd6cd1100a8f4ebdb602381235f5075135f1c21cf6b5bcfb99e3fad801cb087ce86945673ba2272b58c60125f8254b0e9b9953ad6fef92a9e96a28ee9969fee45d13013e038025ba19a549e6184ff23e23ee1c8d0d9cfb5d4fecda271249b285a19ac06bc44c5fbb5da957ea1b181eee5f110759a655ea770a3f731c9dfaf981a0241f9b3a509d0971f0797
#TRUST-RSA-SHA256 58a084473e6273086622f3e28600999c0fd287f4dff21a51cfe5528eaa49bb97566455c0185838f2cde64f5a1fa44415f2f6d81910a35ed608d6a9103c82c2b8ef16af9f2f4d9a56f0f1cf5adedec00bbda0eed557f1d42d35013670dd322ffba2a2405f35ba93c1e7f4ac8900282612d649bf0934ee62227385b21acd1ad10ec712a4510955c5f1e79310e5aa457e3f901d8fd1538f73e1bfd14171e6a5c4fcc8d9ba73c56c4276dbde5549ee4da93ad88eda65e87fd52d3bf3955c4ad3e3b252ba6e77c3666012eb2b47788ad243348c60c7d606b251eeaa95e67ea1b53e83278e7a7ec273553fb7d78b751913c4316a99a98263e2b3ae61da9539e57647c75ff005c8f3a3b612e8e0c27da9866b704fbc67cc71b12ac647bb00dd59125a84d0e0fb4941f9c0352f84685c7d46d7f60bfeff90f82a67904cc1cbeb8b59b511f1599c0b4f9deb2c81bc6f816f0712a241982312c4d695b4385fa1267d4397f9f7e1deec88e7a5a814bfb7cb6d46f0a2f3bc5b8c7659f7aeb93b1d4580acce432ea56bc36733b2fdeb286ac490d132e6a7622799029a8e9fe67d8a2624c36a6f6fa34cea98b0bceae41ebd65f7682e1f478ecd737e6927ce0a30878cf1f18f223401e0d489627cb34397f0947fda62b2e57936678bced6c71e41f80981c34a59b6aea759bea813d7f8a0d7180325f65f54639ebdaebcd34d225d579d5d202342
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(183777);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/10/25");

  script_cve_id("CVE-2023-20233");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwd75868");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ios-xr-cfm-3pWN8MKt");

  script_name(english:"Cisco IOS XR Software Connectivity Fault Management DoS (cisco-sa-ios-xr-cfm-3pWN8MKt)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XR is affected by a vulnerability.

  - A vulnerability in the Connectivity Fault Management (CFM) feature of Cisco IOS XR Software could allow an
    unauthenticated, remote attacker to cause a denial of service (DoS) condition on an affected device. This
    vulnerability is due to incorrect processing of invalid continuity check messages (CCMs). An attacker
    could exploit this vulnerability by sending crafted CCMs to an affected device. A successful exploit could
    allow the attacker to cause the CFM service to crash when a user displays information about maintenance
    end points (MEPs) for peer MEPs on an affected device. (CVE-2023-20233)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ios-xr-cfm-3pWN8MKt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8176fa6d");
  # https://sec.cloudapps.cisco.com/security/center/viewErp.x?alertId=ERP-75241
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6a0abd7f");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwd75868");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwd75868");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20233");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/09/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/09/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/24");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XR');

var vuln_ranges = [
  {'min_ver' : '0.0', 'fix_ver' : '7.5.4'},
  {'min_ver' : '7.6', 'fix_ver' : '7.6.3'},
  {'min_ver' : '7.7', 'fix_ver' : '7.7.21'},
  {'min_ver' : '7.8', 'fix_ver' : '7.8.2'},
  {'min_ver' : '7.9', 'fix_ver' : '7.9.1'}
];

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = [
  WORKAROUND_CONFIG['ethernet_cfm'],
  WORKAROUND_CONFIG['mep_domain'],
  {'require_all_generic_workarounds': TRUE}
];

var reporting = make_array(
  'port'    , product_info['port'],
  'severity', SECURITY_HOLE,
  'version' , product_info['version'],
  'bug_id'  , 'CSCwd75868',
  'cmds'    , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
