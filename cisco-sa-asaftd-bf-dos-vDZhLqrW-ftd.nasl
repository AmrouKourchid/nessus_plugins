#TRUSTED 231e68ab9ebcb66cabe482363f51cdc95834c8e112401d3344de846276b0ae0081cdaa81d6020205769767df5af7930d7b119389dbd0a7e6f9b706ad3397e9039b852284a8f13f8899b432e2ffc852c985f46690f13a92754d17ff158bbc109519105bed0ff239609fcc2d955aa23131ab3e09316056199593d8f5a2d5dcf726f728e889d0ee0f96e3541d889421fb4a3834c671e17954fd5ebdfea2115f806152a0c2b39109d856560ed2bad3423e6a3f4305dc2628736767f55cdedb6bc560e64977ef2dcfc96990bf36e151d1b17c2ef174bae2fc71c0873eeadb857ff0ee9c61ebf97453b5318126322fcdce4f1e03aa33465932d79c0db912e3f5e0610364d08cf584f7bb00eb9e3528df0036a8fb29107a966e63805aabf976b40022a135f5fb344adf411d17f4c414007150e1076b8b81eb3c5f320da6beed7cd06f95cfb401f533046bf07170bae46d46b69c00d0ccb90f1466cea4147c4ba9c4d88f3193f5d07ffb9308512d2d1bd658d210022d1611bc403bad4b5972d5485e99aad7eaf48cca8c2cd9f8761d19d34329c5729ff7bae5ff14876883a8811dc1c9e1c67f8646dbee9585e9139042a785fd0e68be7a31e5d6d2acbc5bba1069cb48ab161d533bc807e0f323b24098fd2bc6a1e5352098f9d140b327143da07f67ca3e65614d95e043ff0bb41cfdfccdd82ebbf068076ed9d5b61c76aa7ca4a2b0a6c3
#TRUST-RSA-SHA256 022ef497f7c7458d944006b0b60431ebc2f0fb0bee459397e589d35c39d97d99f7cb71c74637fb0b3ef9e6c262ac93fa8bc382513a12d66d64c21d3119428fa470ae3ac719c1fdaa80040cb0cd5e2372ec0a51a4c7050f4e6d39f53a663befaad9ddf9b7492b3d68c5515e849dcb61257cc8413bc6a6f450b1a38f5693943307b6a2799ad4d3213096d02b2eb4809d706b4f0e972702f2c64bf34c97ce7f948a8567859b64eb035c826ca5abfcbfd464fb65e9dc94f154ff37b400a137f44afabb60c5e7263b4c92b50d6d6fe2e1ae55e5c1f1b91c06a96c91b7a8adfe769581f141749377e47a31bc67f8311236405ccabed149138d2b2f7673c266b84f8b0aa01928f1061624b5889662afd5feb062a06ed8aac7c0570aec7db7badf989afb69be65ec307676e6eb9ccf6dd007479c8d4ae2fc0aede9cd80d11f1ec33f0c030846b692b37950bade8d55fb46f8a50fa513f46e911d2b4fdae02f061af46525433d06f91b2a397f6528b5b8b9f383fa0b4732cb58545d21597ed7d2fb2d5ef49252df30c123849c8196bec6f0cc85adaa91a1986774216d39c89180d5ca8a37653a02ffb990769bdf8834efb4092868db0970a88759c1c955f7fc137590873268cde6ae2c5e312a209120c65b958b8f10902b0ce2f3e10a3c60482f369ae7a28f9cd965e4c169e63bdaf0bdbab294f914b277f943879b541e3ebbcfb877d82c
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(209988);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/31");

  script_cve_id("CVE-2024-20481");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/11/14");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwj45822");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwj91570");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asaftd-bf-dos-vDZhLqrW");

  script_name(english:"Cisco Firepower Threat Defense Software Remote Access VPN Brute Force DoS (cisco-sa-asaftd-bf-dos-vDZhLqrW)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Firepower Threat Defense Software is affected by a vulnerability.

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
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_threat_defense");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');

var vuln_ranges = [
  {'min_ver': '6.2.3', 'fix_ver': '7.0.6.3'},
  {'min_ver': '7.2.0', 'fix_ver': '7.2.9'},
  {'min_ver': '7.3.0', 'fix_ver': '7.4.2.1'}
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
