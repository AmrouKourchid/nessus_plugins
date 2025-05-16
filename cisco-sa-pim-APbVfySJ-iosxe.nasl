#TRUSTED 7e4910d1ebab7c2d2e7b5f221cd3d91943c6342081bdd45b7450f2a02fac371b9dfcf0cef091758c8f71feccf81b9c3821fc3f62784795d38a92e2db3e0a82927619c2c02241d5b1996a38791b0a8d1879bfaff53723108855f2ead7806215746c80d392d0a3ae606bbeb3316c0886225bb423536455a000c3b4f24b3443d2cb4d47598b16860d4ea88f7f899f4c17462a7f9aeebe6e03f471852ca373b72a6e74b4b4eadcfddc9126c2586bd138b88ca52f83ef4f591347d6dfa1fcb0648fb3d9a0fd2212d261ec9e0640fb0c4592ec1700f7416c111ce9afde0db4829af015c34c70f1cb5cfd9b42d5c0fc2670ee038dfeb72aacf1a1d307d6c817da5177558c6117054dcd8b2afde3b717df4da71d3e80bb41ed9ea4b1d0bfaffc6097a77f0922b652518c61bcc158017f1311865a770a316fdca459afcda96f892ec38fecaf832dab4aca3e7c0bd96b8992cdcf8a0dbec3c52715ffe160a9f3a9e41df344b03312ec707dbf5c89728aa38e348087ee565e030d5f76e36de8e24adbc2872ef6492970a998a8839ab3619c2adad5ed4f75dbcdf0a1dc6e9960f5354ebd75e7218297abd39562409b0fa6b265181cfa560543b28b25f4ef76c72e72f6a29da2ff42fe6d2d1ec2172f867782b294fed1aded315907349182d2352562a5b7e5f4330dc903ce31ea0f13503a72cb1bd7cb17c7520d3ccdf4fb67d14a4f44eaef65
#TRUST-RSA-SHA256 63437dc3e9e4289f421753fec2f636837d4ad6e8c2e454d8ebeacd95d1492a4d60673c9c6b167234b80f1ed408d458ccd198652d0d35182450252a78898a590078b2819753c22ebdb9788d2a11c6e1144f2ccb3d26cdbf36f2fb838e3d4aadeeea787244e96efdebc5f78b7453d7c619d458b408765051d23229b50788030a348f0b41418053748c8a403075c534144e2c5d1c108b43d439d127faad9aa5e1b5bb6dd7b6e5e9789af0329371c0d80a06b01ae091840575ea755ab67d0aff6bf1264f6ab6e8121b992e022c9ad8b28ab361f99264c9bb3f1c5c5daf25b4d05fba017072c0ae0ee25597c19c34127348c36dcc0b15b88939ff535a57d4342e82800394f1ba9bd14a572458ded6ce16036dcc82dda1056325e6ad8f9f277f4646c98205c0a3fece293116da633033ab6d3f98aa80f5ece6c635b5c04728089943ee6474b49dd94caf606b154d238e5fa0cb292790a9216659caebe56ddcd708b7df352098b1bcc8bb484db29a91a0339527249584bd2c7149233a069ad565370144ac4895cf06a93155a14349a63d9c574a81db98b773055e6a569943236074e3b5bbee8cba8d4fda043735d79dd891146bd0bd43674f3ce1cd43a213a3263dbb4192de3e01a404cbb49d1bc8831673b08c75506d733288a8d4a86679bca2492fc4fae5dcbf863a91c82f2e35678254dc9acb10d88d94cb049ecc08dd226bb58804
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(213440);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/30");

  script_cve_id("CVE-2024-20464");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwi53919");
  script_xref(name:"CISCO-SA", value:"cisco-sa-pim-APbVfySJ");
  script_xref(name:"IAVA", value:"2024-A-0592");

  script_name(english:"Cisco IOS XE Software Protocol Independent Multicast DoS (cisco-sa-pim-APbVfySJ)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS-XE Software is affected by a vulnerability.

  - A vulnerability in the Protocol Independent Multicast (PIM) feature of Cisco IOS XE Software could allow
    an unauthenticated, remote attacker to cause a denial of service (DoS) condition on an affected device.
    This vulnerability is due to insufficient validation of received IPv4 PIMv2 packets. An attacker could
    exploit this vulnerability by sending a crafted PIMv2 packet to a PIM-enabled interface on an affected
    device. A successful exploit could allow the attacker to cause an affected device to reload, resulting in
    a DoS condition. Note: This vulnerability can be exploited with either an IPv4 multicast or unicast
    packet. (CVE-2024-20464)

Please see the included Cisco BID and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-pim-APbVfySJ
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f96b9706");
  # https://sec.cloudapps.cisco.com/security/center/viewErp.x?alertId=ERP-75169
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e0341eea");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwi53919");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwi53919");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20464");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/30");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Settings/ParanoidReport");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

var product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

var version_list= make_list(
  '17.13.1',
  '17.13.1a'
);

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = WORKAROUND_CONFIG['show_pim_sparse'];

var reporting = make_array(
  'port'    , product_info['port'],
  'severity', SECURITY_HOLE,
  'version' , product_info['version'],
  'bug_id'  , 'CSCwi53919',
  'cmds'    , make_list('show running-config | include ip pim sparse')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
