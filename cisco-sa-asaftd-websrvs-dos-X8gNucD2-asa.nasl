#TRUSTED 2df36eead6dd2c7fbf9af9d63e94ddb8f355b6b0aa6981e4ebd306ea4c50d73df280829657cbceea276f246769239b8609aae5c7757224c9e93ba419f40d70c94141b39edae15687bf96f36d11a573f954fa9bebadba6a487f55e4a015443f28f143568647454d437c476dc529070c675a9c37f53f1b34db97d9fba0ddb4b04cc7ea079eb4a46bc0c3392e84fa3b888c99faa009a8978214b2dd6a889674c0075f6a3e65379294cc1b9959d39df2814a96955c49cbf127c93c5353f7e32780b40203818769ad4a5ea7e90acaed72d4b8d1c98747c7e6e76a724b1c7da07ca466f41da47b98543458f5b4ff9cf4a9b1841bcffdb039ba05add8d9230577c3e1ba432a268e5d7f9df894b33caeaf1f7188fefb73a3b33616272176d783b21f3cf7a44b39ddb148b5bb3ba0d67214dec7034e2b39516d870a9793c07755ad985b875585c112e5f4283467b708f20e37489c5995df6776f5d346a1c1fc17d6aedbf1c0be7bbb9d5a759f2895014411603f7a9ed4a5156e634ea34932ac949fa2c1086300aea9a8179a72f6273f7fd424a7d13df0d585d49751919edfcee7058dcb7f2f38d0366f0702af0b8d5997fd5e3a28047c8729bc228a5d821d6615ba4ca5bdf990291074231a247726e9b48b079d00a139ddc7d55c88bf99f558475b3c9c847d9fafd38aebe8da7e2f266136cab63be9a15d808b17640c005d1ef99f3f1176
#TRUST-RSA-SHA256 9606fb1832ba10b344006b4465cd52225e01e5553b4564b60170c6bea4e7573bf4788f7e7c1b5a1b161a9ff574d3e54176e119a09969cc5e66de324829537e391090025ac54dbc1ce6e76143bf4c64cb9acf5eca95f968c3ba6a9184b11384566bac389c455eafdccc0e07cdfe1fd66c9990c4611a92a39cecf51c91d4edd11d73b0f17b94acd3a2ad674592f1f0a89a09ef4eda764250f20ba40c8343e0145a5dd4edaf0bf638f7d190f1cda31f86ebf90b9488a493125d95d5c236cb740736b096dcefd2680bd236a95417755ec37a95755667f7af41ed66c9b80d52e1f5a9cdd60abf6317870a97ac8ba53bc1d688162237beb98ba38d0d85eac42fc58561eecfe2615de8ab7b32aac48d375313a5adea0124ce46ab2f402816785d616918241c8adfb8c901b0d2fc3c5847c86ab48447fe4682a4b8e538a4ad100080819b91ea815f1f62f3a9d8bd93739988d72cb5ee93efb1914ea72c321c3d612402b00312e559de689d369b864b37b966a497fde1039a4d08ac85b02f2916397f37aeb27662825af53c6da2e415673ea8b54d49a96bbfb7cd9e1d92f240ffaf5e96afb6038327d1b569967b93782e404f67569eb6858199fb2578c67f0b6d00efee9e803aaca291159f8a18739af42c356bcb71c84b3cd37613a6d9b85ede35b2ebb0056ff7490a4457271b5b69e65ca97c02d557fd409305cf4e2ad3a51b1ca8ae33
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(193915);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/31");

  script_cve_id("CVE-2024-20353");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwj10955");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asaftd-websrvs-dos-X8gNucD2");
  script_xref(name:"CEA-ID", value:"CEA-2024-0007");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/05/01");
  script_xref(name:"IAVA", value:"2024-A-0252-S");

  script_name(english:"Cisco Adaptive Security Appliance Software Web Services DoS Vulnerability (cisco-sa-asaftd-websrvs-dos-X8gNucD2)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the remote Cisco ASA Software is affected by a denial of service (DoS)
vulnerability, due to incomplete error checking when parsing HTTP headers. An unauthenticated, remote attacker can
exploit this issue, via specially crafted HTTP request, to cause the system to stop responding.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported 
version number.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-websrvs-dos-X8gNucD2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d89c58cf");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCwj10955");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20353");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/ASA");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco Adaptive Security Appliance (ASA) Software');

var vuln_versions = make_list(
  '9.8.1',
  '9.8.1.5',
  '9.8.1.7',
  '9.8.2',
  '9.8.2.8',
  '9.8.2.14',
  '9.8.2.15',
  '9.8.2.17',
  '9.8.2.20',
  '9.8.2.24',
  '9.8.2.26',
  '9.8.2.28',
  '9.8.2.33',
  '9.8.2.35',
  '9.8.2.38',
  '9.8.3.8',
  '9.8.3.11',
  '9.8.3.14',
  '9.8.3.16',
  '9.8.3.18',
  '9.8.3.21',
  '9.8.3',
  '9.8.3.26',
  '9.8.3.29',
  '9.8.4',
  '9.8.4.3',
  '9.8.4.7',
  '9.8.4.8',
  '9.8.4.10',
  '9.8.4.12',
  '9.8.4.15',
  '9.8.4.17',
  '9.8.4.25',
  '9.8.4.20',
  '9.8.4.22',
  '9.8.4.26',
  '9.8.4.29',
  '9.8.4.32',
  '9.8.4.33',
  '9.8.4.34',
  '9.8.4.35',
  '9.8.4.39',
  '9.8.4.40',
  '9.8.4.41',
  '9.8.4.43',
  '9.8.4.44',
  '9.8.4.45',
  '9.8.4.46',
  '9.8.4.48',
  '9.12.1',
  '9.12.1.2',
  '9.12.1.3',
  '9.12.2',
  '9.12.2.4',
  '9.12.2.5',
  '9.12.2.9',
  '9.12.3',
  '9.12.3.2',
  '9.12.3.7',
  '9.12.4',
  '9.12.3.12',
  '9.12.3.9',
  '9.12.2.1',
  '9.12.4.2',
  '9.12.4.4',
  '9.12.4.7',
  '9.12.4.10',
  '9.12.4.13',
  '9.12.4.8',
  '9.12.4.18',
  '9.12.4.24',
  '9.12.4.26',
  '9.12.4.29',
  '9.12.4.30',
  '9.12.4.35',
  '9.12.4.37',
  '9.12.4.38',
  '9.12.4.39',
  '9.12.4.40',
  '9.12.4.41',
  '9.12.4.47',
  '9.12.4.48',
  '9.12.4.50',
  '9.12.4.52',
  '9.12.4.54',
  '9.12.4.55',
  '9.12.4.56',
  '9.12.4.58',
  '9.12.4.62',
  '9.12.4.65',
  '9.14.1',
  '9.14.1.10',
  '9.14.1.6',
  '9.14.1.15',
  '9.14.1.19',
  '9.14.1.30',
  '9.14.2',
  '9.14.2.4',
  '9.14.2.8',
  '9.14.2.13',
  '9.14.2.15',
  '9.14.3',
  '9.14.3.1',
  '9.14.3.9',
  '9.14.3.11',
  '9.14.3.13',
  '9.14.3.18',
  '9.14.3.15',
  '9.14.4',
  '9.14.4.6',
  '9.14.4.7',
  '9.14.4.12',
  '9.14.4.13',
  '9.14.4.14',
  '9.14.4.15',
  '9.14.4.17',
  '9.14.4.22',
  '9.14.4.23',
  '9.15.1',
  '9.15.1.7',
  '9.15.1.10',
  '9.15.1.15',
  '9.15.1.16',
  '9.15.1.17',
  '9.15.1.1',
  '9.15.1.21',
  '9.16.1',
  '9.16.1.28',
  '9.16.2',
  '9.16.2.3',
  '9.16.2.7',
  '9.16.2.11',
  '9.16.2.13',
  '9.16.2.14',
  '9.16.3',
  '9.16.3.3',
  '9.16.3.14',
  '9.16.3.15',
  '9.16.3.19',
  '9.16.3.23',
  '9.16.4',
  '9.16.4.9',
  '9.16.4.14',
  '9.16.4.18',
  '9.16.4.19',
  '9.16.4.27',
  '9.16.4.38',
  '9.16.4.39',
  '9.16.4.42',
  '9.16.4.48',
  '9.16.4.55',
  '9.17.1',
  '9.17.1.7',
  '9.17.1.9',
  '9.17.1.10',
  '9.17.1.11',
  '9.17.1.13',
  '9.17.1.15',
  '9.17.1.20',
  '9.17.1.30',
  '9.17.1.33',
  '9.18.1',
  '9.18.1.3',
  '9.18.2',
  '9.18.2.5',
  '9.18.2.7',
  '9.18.2.8',
  '9.18.3',
  '9.18.3.39',
  '9.18.3.46',
  '9.18.3.53',
  '9.18.3.55',
  '9.18.3.56',
  '9.18.4',
  '9.18.4.5',
  '9.18.4.8',
  '9.19.1',
  '9.19.1.5',
  '9.19.1.9',
  '9.19.1.12',
  '9.19.1.18',
  '9.19.1.22',
  '9.19.1.24',
  '9.19.1.27',
  '9.20.1',
  '9.20.1.5',
  '9.20.2'
);

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = [WORKAROUND_CONFIG['asa_ssl_service']];

var reporting = make_array(
  'port'    , 0,
  'severity', SECURITY_HOLE,
  'version' , product_info['version'],
  'bug_id'  , 'CSCwj10955'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:vuln_versions
);
