#TRUSTED 50d0819f6b04df27550f689750a9b613f838944c075273944260c4e27186c368d59493ab882032c5b160304984cf298274503af810a0d219681662659bf1ed3d7903a6d32ed98ef010c20c13186a1c72f802c069e437cf58a5e95332b9a24d192f3d2801a492f184472e314a8be5cbdaee9676361449e0d51b03b54ae980139cc6e779265bcae5240fed959df7db292a1a5439516ff01e1e2ce9c1cde0e9c79f608e8c23d20519581b29e2c1bf3b949a7f700dab9b308522f5fc6c78489e7ead83ea20952c4aceb0cb487b343f2ea5965bdbb0c8faedb0fff6cf2d645c484847ece466be4a6632c3de1ad34367fb7e1abd76544a4a3626f3d5dc43ec46cb2104e1598564765e5b74aa493293fd750d9dad59f9ee6c4f356171389255de93a7bccc8fefd198faa59c26c9facb4158d50cf1bda856b94ff73b46e2c549b2d0e02e10490110e2c5414978c639f6837db6d365ce1367b4c449795012936b218e5ec969123317eb516f8faca21181807b930670d6f2c347ac91a6a9aeba97d33d26732283002c0117eb69bf3e5f094fe116bad4df860aa3c7844ace3120a6852d26010ec45920833d5805246c4b03141b53d59e9e4bf5b6c2137ec64efa4a5ac33aee5333e0417543e2b9eb340f30301fdca72ed0e5ee68a360a99ea001e7a4c8fd92fe4d6101ece2db803f4a93ccb8b549f237112f8a121b712029072e6b73d8f48d
#TRUST-RSA-SHA256 73f8e6a168d397130f6ee945cbb6d2b908955f88407623f85418a9f6984f991ec75e32f5e66850d3d9fe8658979cbda54a7be6c7e2e5eef3385fabd5a226606f4fd253ac25be99366020710e17dede9a962beff5a1e4a529a861ed20c9dc39c2745e57ff167e91f32e078cba91f3dd69e4b81e7639aa5d9b1a35d722f0bd0a46efa597857400f9443d9161a656bd38c5ff58b9791d1ed31e3e80448d189c0f71faa0d680cecefe4b104a650e01ec284ae701739c1989bffbea126dcf4609c53200321056c199262e523d161561919f359a71c4e1ef864cc9313939b06195a78543bcffade2cdf2259e8e2df393f5e2ecb3494375b2aa8d4328724e9076f8608ee7637c46a34e6a987be956707debffaafb2b4102d271a8d190f27c52e246f87ff460e19b218229f1a0b7e342248a6d975bbabd313141844506e0d1ba6611540c8c5b6edf33366b1df6f69af9eb3002479c44af37cef53c49da2eb53fe6167e58f3e0267c2a422ba0c6598db626d5860b9c0bef2cea2633cacd965bbcb3bf592f3bdac4045050e1ebd270254a9ac201cbabb09438393d584a9b531dc4e6c354776fc816ec6ddcfb62fb1d9c2b3ffa548604863b341af8a4419702f5ca15f1565c4b2ba71a2f86aa7303f26533fadff926d47e73683ca4ecce009f02ce364e6a8ce1b892796b77fc03da58a0ae0c123980f958b14d512727059ef397f69b0e2be4
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(137073);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/21");

  script_cve_id("CVE-2019-1590");
  script_bugtraq_id(108133);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvn09791");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190501-aci-insecure-fabric");

  script_name(english:"Cisco Nexus 9000 Series Fabric Switches Application Centric Infrastructure Mode Insecure Fabric Authentication Vulnerability (cisco-sa-20190501-aci-insecure-fabric)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch (cisco-sa-20190501-aci-insecure-fabric)");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco NX-OS System Software in ACI Mode is affected by an 
insecure authentication vulnerability in the (TLS) certificate validation due to insufficient validation. 
An unauthenticated, remote attacker can exploit this, via certificate manipulation, to gain root privileges.

 Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190501-aci-insecure-fabric
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fa077983");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-70757");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvn09791");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvn09791");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1590");
  script_set_attribute(attribute:"cvss3_score_rationale", value:"Scoring adjustsed to align with CVSS 3.1 attack complexity guidance.");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/03");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Model", "Host/Cisco/NX-OS/Device", "Host/aci/system/chassis/summary");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco NX-OS Software');

if ('Nexus' >!< product_info.device || product_info.model !~ '^(90[0-9][0-9])' || empty_or_null(get_kb_item("Host/aci/system/chassis/summary")))
  audit(AUDIT_HOST_NOT, 'affected');

vuln_ranges = [
  {'min_ver' : '0.0', 'fix_ver' : '14.1(1i)'}
];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvn09791'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);