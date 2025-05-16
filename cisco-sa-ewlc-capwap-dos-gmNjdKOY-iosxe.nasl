#TRUSTED 0088d47930b7489f51b1331d5a78bcd7e7212a24fb689c100f13def65de0b7dff4614fe96d8f643556e9d0547fe4272279528ac93c6a675c30cb4dd3b46651eaad99b712a04c8ceb3088f0e940d9b222fd8d8358e73605df588ee935709a136e753f5ddf5ce6a33bd108b1b9030b552173d7e3fc41cee95ab2d5d3227867b2191b28052acd1a536bc45c88e0a761b108fc8ecc0109492582f34ee04a55b2cd65a28d50ee93511526ad912d81dce63d19eefbb0813bd5316dd15ac044487f478df1ef2d5431be421877629a6208e2fb9a3fd1503685adc659c0bff468c6a9ee818f722630a9d6cdecfa8886f2bf3f9c63f09af6ff0c65cf0c63ee986ff86f0c8286cc4c15f2031edb7153d9d39c62c737619c44715a31d5dbdfc93ace0f67cbc5942e7db2a281c7674a1e348a3db70fe056453409534f614b55738b70b716a1b5ebe1c97f2d30e5d786799471cf9aab5e43db15f889583d08bad602e8461e0ad103f169b0e67ed44b28d68c17e71c81ea210a56efb053ee2fd61d064fe6f3761d82931cd98f7edd9a2aa7c3cfe0f2b41b1cf91bbc1a1fd892e2f2a3f7e9b595d8a7b2fe7fb3b373d3ec0991f1a9b41aa3b5a29e124303abab26f891086c1ddeac33f09447409a73965399ddadcec23df835e8fd98dfe30d6fc6d8178751c507b595bdfd21ea6bfc6d5e44a004f917cd35b6817e812c0950c6ad8cac508a0ebc12
#TRUST-RSA-SHA256 1fceea4ded95873afd81a99adabb7066c6ffce303c516069b30c5aaa2f22bd7309998181c18b6da7ee6856689335aa23bc9b5c50ace8edb9a57cc3f1a79a6d7b4491b913e6a969cf56756a6dec06ccb697944cb603dc6837efc80d37356b5aa96a23d75ea48914ce426ea42c7232ca2c7f1860ef3c9963b851c8973937daf780253a75cde358c741477e93554c99799af46253e10aeee3755e8aeb6fbd6b124a4be199af007cea9450588e53c15c39c3fc3072e8e533dc3965782b675b3a16d249a7420225cb9bdd9cefdc662a4151e1ca7984a6a0b6eb666f86ab7895f19e9929f5be97a69e7b865ab56d52b58d03d2aa25d7c572358c6336df5110207c38d99574d86198bfbeb2b1daaf7df6f5b8e7c999d51928ff19a8c73cea738aa4d932822bfb13c9b9eda79cdb9f3b0eedf6d9bb262db87b8b01dafd6bb475b5da947d7dce1ec529d7535d2a545df955d1b4917812fd33830833b901829f25426454fa13aead1af59bf40428e26e60726116b8caa2265c0b277068924255bc73a55ff2770f26be7bcb72d0c131c13a25ea8a9ce2fe35a48b623a0fcfbde70b9da8fd5045b8812f949d8c717b40cc2727f4346ecacd0465bbfd7374568601a142512045f0d2150da7c834b4a62a727290103bda481ce406a06a9da799ccbc283ca19b0e3e1c278caccb880d04ff9409426a02be9ad3c0c39ebf52a498fa6c520ea69c50
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153563);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/09/28");

  script_cve_id("CVE-2021-1565", "CVE-2021-34768", "CVE-2021-34769");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu73277");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv76805");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw03037");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw53824");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ewlc-capwap-dos-gmNjdKOY");
  script_xref(name:"IAVA", value:"2021-A-0441-S");

  script_name(english:"Cisco IOS XE Software for Catalyst 9000 Family Wireless Controllers CAPWAP Denial of Service (cisco-sa-ewlc-capwap-dos-gmNjdKOY)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS-XE Software is affected by multiple vulnerabilities.
  - Multiple vulnerabilities in the Control and Provisioning of Wireless Access Points (CAPWAP) protocol
    processing of Cisco IOS XE Software for Cisco Catalyst 9000 Family Wireless Controllers could allow an
    unauthenticated, remote attacker to cause a denial of service (DoS) condition on an affected device. These
    vulnerabilities are due to insufficient validation of CAPWAP packets. An attacker could exploit the
    vulnerabilities by sending a malformed CAPWAP packet to an affected device. A successful exploit could
    allow the attacker to cause the affected device to crash and reload, resulting in a DoS condition.
    (CVE-2021-1565, CVE-2021-34768, CVE-2021-34769)
Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ewlc-capwap-dos-gmNjdKOY
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0ab5cb4c");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74581");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu73277");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv76805");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw03037");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw53824");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvu73277, CSCvv76805, CSCvw03037, CSCvw53824");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-34769");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-1565");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(415, 476, 690);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/22");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/IOS-XE/Model");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XE Software');
var model = toupper(product_info.model);

# Vulnerable model list
if ('CATALYST' >!< model || model !~ '9300|9400|9500|9800|9800-CL')
    audit(AUDIT_HOST_NOT, 'affected');

var version_list=make_list(
  '3.15.1xbS',
  '3.15.2xbS',
  '16.6.4s',
  '16.10.1',
  '16.10.1e',
  '16.10.1s',
  '16.11.1',
  '16.11.1a',
  '16.11.1b',
  '16.11.1c',
  '16.11.2',
  '16.12.1',
  '16.12.1s',
  '16.12.1t',
  '16.12.2s',
  '16.12.2t',
  '16.12.3',
  '16.12.3s',
  '16.12.4',
  '16.12.4a',
  '17.1.1',
  '17.1.1s',
  '17.1.1t',
  '17.1.2',
  '17.1.3',
  '17.2.1',
  '17.2.1a',
  '17.3.1',
  '17.3.2',
  '17.3.2a',
  '17.4.1'
);

var reporting = make_array(
  'port' , product_info['port'],
  'severity' , SECURITY_HOLE,
  'bug_id'   , 'CSCvu73277, CSCvv76805, CSCvw03037, CSCvw53824',
  'version'  , product_info['version'],
  'cmds', make_list('show ap config general')
);

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = WORKAROUND_CONFIG['check_ap_capwap_config'];

cisco::check_and_report(
  product_info      : product_info,
  workarounds       : workarounds,
  workaround_params : workaround_params,
  reporting         : reporting,
  vuln_versions     : version_list
);