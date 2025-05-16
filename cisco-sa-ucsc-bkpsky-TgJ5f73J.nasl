#TRUSTED 8aed62458d7672caf6400738bdc7fc9c971d0e4eef90907cc1d14ef4b689385ef8c2d1b7c42a1b4b2266925ca2ee38607f1ffd86e60a38236a39aab1b753bc783fb762e19947fcaa2138bed92c232984b4ae87de90b4476da94e3944eea955abc8a38db00b3e5e1a71614ad5d78568251aa24b0f05aa5f6afa8af4f90bd17e4e16f0768cb16011429d65d113624847d43d38554fc7a1defc91bc3c1eb9615aa21b0a70562b542f0bd952c51f7c14c6180ee3cf149eaa72af46c6d8b396bfe4ccb7486244e59e5e789b93b627b5353c7f20739ed5139d847298d744bbe405a71481ed086c0cee7a365f2d427ecaeae86182a6f1b89b921110315f9871ee9dd6772cea0afc98c99346ba297ec87640c526c1371fd336b5a9dfbd61bcd99e2cb896f924e3b4e4014d8413b1630b04b5a80d2bfcc8083ada464caded1f309b657e51f89b8bc24052aab5f8fd6494ee1613631814dce4bedd606768f7fd5545a88f80515e35c9a16f782b19a85ea326d8512a80e4d0085e16b5d97a1b09c3e856d23444d6bc506ed0ca88cb0b0d2ecbc8cd5f78af22345b03d815aedac5c0bc6c7af01328381588f9c43d57d0d58f02cbe112e4a72aa56b76530cbe28c09d01f6a74cc0ac3db25f997977a3508e5b63a3ac9147705bc883e39d8f588964495a18da92ede3e7418f083b971748da4993c7bb5317fe5da1b95b3524bf52ec1d33f8e4fe
#TRUST-RSA-SHA256 98b6c0b82b4b5a7ecb271e049eadcef4f746260ab6664073d6d4eb8ba50a2bde2075c624eed57a4a08e3db45605fed5fc9f39f5b453d2485b899c0bd95dca3bdf1240a0f14f28d63f93fa5d6d457d3d109f96991e274254d4e80224bc893cb8a1f020b9fb1bc865720446d49230b7e55817d56d16f18ff6cfbce1b083367df58423b065816d31bcc8b21a443428db6d7a9a692cd067f6d0d7496d697f83630d378ce1defe9d1cb58538c0a162b7b3bf1eeedae646a3fecead72a2c44b3574c114a30b74baab1c866490daede00dc052dfb44d9fe01cf37e570c51d88ef52714cfb399a766ca540691f20e6e29a592dd73c66a95857795f85b98bc0f7f063ba4bc825c84f4ca01ee7a79a059d64c712dc777330c952f4843c338c773ddba285b7435ea656218582e5aa5ffba1731f4b7031efa2453e3031bd1a47ead8f9c4ea23da7f461347bb1d8d92d3fcf9b7f355427c0f71e4165329a0928ab99e7ab39e811105177c30abf217e7e1f39f9da8e84c631edadf0c5798c0c5df7361c7070b1a8e6fd21f2c089ae970fbcc65e33e693ac947a26f38c8a007e931efc46e9f997ded13d5210db1767593a960226841d3351d1bb117a9c59856ead6b6c6e27a90e3f0075015bb021a53d6be594d37ac5b1da479150f237bfe60092951fdd1cd0655712c18748bb695bd680714cbcfd891cccf91c810b9dbe4852d8b6c04cf1ef416
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(209303);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/18");

  script_cve_id("CVE-2024-20280");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe23286");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwj91571");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ucsc-bkpsky-TgJ5f73J");
  script_xref(name:"IAVA", value:"2024-A-0675");

  script_name(english:"Cisco UCS Central Software Configuration Backup Information Disclosure (cisco-sa-ucsc-bkpsky-TgJ5f73J)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco UCS Central Software Configuration Backup Information Disclosure is
affected by a vulnerability.

  - A vulnerability in the backup feature of Cisco UCS Central Software could allow an attacker with access to
    a backup file to learn sensitive information that is stored in the full state and configuration backup
    files. This vulnerability is due to a weakness in the encryption method that is used for the backup
    function. An attacker could exploit this vulnerability by accessing a backup file and leveraging a static
    key that is used for the backup configuration feature. A successful exploit could allow an attacker with
    access to a backup file to learn sensitive information that is stored in full state backup files and
    configuration backup files, such as local user credentials, authentication server passwords, Simple
    Network Management Protocol (SNMP) community names, and the device SSL server certificate and key.
    (CVE-2024-20280)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ucsc-bkpsky-TgJ5f73J
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c636e758");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwe23286");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwj91571");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCwe23286, CSCwj91571");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20280");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(321);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:unified_computing_system_central");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ucs_central_webui_detect.nbin");
  script_require_keys("installed_sw/Cisco UCS Central WebUI");

  exit(0);
}

include('ccf.inc');
include('http.inc');

var app_name = 'Cisco UCS Central WebUI';
var port = get_http_port(default:443);

var product_info = cisco::get_product_info(name:app_name, port:port);

var vuln_ranges = [
  {'min_ver' : '0.0',  'fix_ver': '2.0(1v)'}
];

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_WARNING,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCwe23286, CSCwj91571',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
