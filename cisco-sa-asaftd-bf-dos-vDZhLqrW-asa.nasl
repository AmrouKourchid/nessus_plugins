#TRUSTED 9acfce9210f5a268904499697b99598a7e6d23f85e5e79dbf3a94679ff6273eefa8599ee883125471e1fd4469e1f4b463cb9e5fdcd017db1cf3cb76e3c2b8d3f4d189a1ba664b52c31cf3a8725765688266b2328eaf8601328886eaa04913fc42ae3405477da3a2a75026487bee27b146a0506fca502c2c4f07ab519aef8015c54387a6237b69a9c9d633115f0655f17cd7cec42cda412445ae81d9122197100d686d62ce6af7e76e11e5ae111d1342acf36c4ef12238156df6583899b85a68a32c98c4653e77c8bd3e9c39455839cfd8e1db0d421077646e1d8837960a2bffe9a7de69c1ce4ccfe6c11b58e2ec1c0b34ad0a0114e8e1c575b4bfe6880e5725432376e2a62cfe7c8aad198166d595a1dac25235474633157bdbcd4a8d8b1aa7170bddc835f9aa6ef29d150c1833e6bcfc781af32032bd555def500256519f9a737c7c2cad5de14fb8d6a191e75ae384df7bd9c7c466370d486093742c904aaf50f0e90cb1d6d380c89744e459ae8539d58c29ae09a3aa951df24021f30e480200ab12a029db7eeef4fb1c8379abf5143a12bbbd61300305d7126656b88cab6c88e62349255c21654106c4bc6598a6f13a712f8f70c166af669e62b201f7274610800a8ce971d0629ea9f2a581269cd4ab91744597a2453123d5379ddf62b9b2c52f84347a990bf238b0e6cff4ee577ef95c27c2240e607cac0292fd8d81ba314
#TRUST-RSA-SHA256 71d8016194e732e9d781f4eab471480bfbb6e4308869a6d6367a9eb57a658b9803679f6a0af9ed9f02f8de1d05f2a1aa8ff2a6230a41d4cfd2d258ee4c09f7839ab19b200de416c7c70ecf01037e663c32ff29f9eb229f0e677f77e6e7c4a0a51c691db02921bde58b6270393d72945182a03e380517c6d500ba1eb16ccb8c682460194834f24e7ce26b14b1865e4ed0cc1e7d9abcae8d6d8c03fd23b7b6170ed530e957ccc7aac3676c7a74ba22dbdaf317c2712722fa3cb49dff47d7319dae22dbcfdbe3959d5198bf35fec6c375be23c060e3d075b21e127a0658534d6552f9b3de1a704794f29d637fd5f92f12a5208f4ce8f54db53c1b39ad6795749e5c57b65950dc5650e00611cc426ea952838f3d9c29c40c2d84c3e0b591901d56d57758fa28c2970d3fca5121f066a0e84fc72a0533fdddc9dd61357ef1b2291f693a8126b28ca465ae34d22821ac02e984ee11bef72ff15b3bccba1a395542f2871fa0a02c2aed56e48c4c775222f7bf90987427fd7abfc2472a506cc01c449c29ed2d5c4749549b1cf8c7297e48332c3e3f73e5086f8f73a3322ae5cbd4270e5be3e6a6cd38525ffb389b33208371b5c2968ee5c3bd894467fbc02e7c8dc5ccb8d8aa9b1fcb97e4196140ab21e77caa8b3a4995b757b0b7ae20a05b1340b09ab115e67d63cc09123c58a65cc6b34b1e4a746fb9840e912e4de8bd1a45f17bfdaf
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(209987);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/31");

  script_cve_id("CVE-2024-20481");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/11/14");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwj45822");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwj91570");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asaftd-bf-dos-vDZhLqrW");

  script_name(english:"Cisco Adaptive Security Appliance Remote Access VPN Brute Force DoS (cisco-sa-asaftd-bf-dos-vDZhLqrW)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Adaptive Security Appliance (ASA) Software is affected by a vulnerability.

  - A vulnerability in the Remote Access VPN (RAVPN) service of Cisco Adaptive Security Appliance (ASA)
    Software and Cisco Firepower Threat Defense (FTD) Software could allow an unauthenticated, remote attacker
    to cause a denial of service (DoS) of the RAVPN service. This vulnerability is due to resource exhaustion.
    An attacker could exploit this vulnerability by sending a large number of VPN authentication requests to
    an affected device. A successful exploit could allow the attacker to exhaust resources, resulting in a DoS
    of the RAVPN service on the affected device. Depending on the impact of the attack, a reload of the device
    may be required to restore the RAVPN service. Services that are not related to VPN are not affected. Cisco
    Talos discussed these attacks in the blog post Large-scale brute-force activity targeting VPNs, SSH
    services with commonly used login credentials. (CVE-2024-20481)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-bf-dos-vDZhLqrW
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a871e3b3");
  # https://sec.cloudapps.cisco.com/security/center/viewErp.x?alertId=ERP-75300
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?900fd680");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwj45822");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwj91570");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCwj45822, CSCwj91570");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20481");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(772);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/ASA/model");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco Adaptive Security Appliance (ASA) Software');

var vuln_ranges = [
  {'min_ver': '9.8.1',  'fix_ver': '9.16.4.62'},
  {'min_ver': '9.17', 'fix_ver': '9.17.1.45'},
  {'min_ver': '9.18', 'fix_ver': '9.18.4.29'},
  {'min_ver': '9.19', 'fix_ver': '9.19.1.37'},
  {'min_ver': '9.20', 'fix_ver': '9.20.2.22'}
];

var workarounds = make_list(CISCO_WORKAROUNDS['ssl_vpn']);

var reporting = make_array(
  'port'    , 0,
  'severity', SECURITY_WARNING,
  'version' , product_info['version'],
  'bug_id'  , 'CSCwj45822, CSCwj91570',
  'cmds'    , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
