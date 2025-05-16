#TRUSTED 72bce8601d66bf485d3555fa5f2709bf51660098373143d805ddc08901540361e45e79fd28ebb66d30b7a353770b29597b31a5271c1a91775cdf650034fd75c8180b0619e706f2187df66ba849fcba96e8f92deba570c552d3f37a1363a8f9124934512bdfbe62a5b24884d26b3d87f756fc2a9f50c761507f6c81e265a5faa35e587a275f9f06acf3e5c466ba77df7363fab6e56e1a2c8d8cc890e826d533c0ca2f2ff948cfa18e4d086f1e58afb638424fe7e03c6af6c6368c7d9ae21c6c4ace408116af455a1c63478ab3b6b5ccb6bb8482c87a25e3a3965c20c0fd60c75560aea4d90598fe51e1bdfbfa635de5403ebc0bee981f2bb0e4d9fc59c7c657884be632b87d6a898cbab19496271a0330854b94e5888600e6106c68e36ca2a377972366c195658ff2a0679acac8bc5409d4a505b60ba803f15c0b04e18356b6031b77ab8549c95509071a2b018def5c6ad8db44b1b8ec64cca54d9964705cb8538d9e9f9426f431e55d763dd0d809079d604343ece53a552c763ccaf9cb6aa71b1dc5bf131659a02dca7c10cb649e1b00b62f1034c7b3932f008b341ed740031a57704f6e492acdfdd8e306f18a93e6d4710496ec5cbde7916b34684dcdd886e143bd2dc805920d8367f5ebed36b310c573e67cc767d3e1d5370b690cabe547458115370a12acbe2efd7aa3a7778a5733f82deb3a1bc2a99e901407183c6eb784
#TRUST-RSA-SHA256 96437283ddce4589fa9fd33799653af6c45d9b88e4428430c6b4c6d7f1e2849b6dadb1ec7f042bcad458d88ab3ef6db18f144940166e68d08cdaaf94d3def8824c3538773baf990b6ea6c39789acced7ec82d19d8ecf8aee4f2c40d2fc7856ef755ddbe5ce9ef913e350c882949eb33992d3c84218c9edbb9bcfbfd8d86fcc3a042559cd05ff4b696da335c1bb52b4f880acc0db8d15a46d3c4844ded753df4693c8b2150652a4627735f24d75358cf5886b21d13cd5ea79ea5e198f2992f3587d179ff2b68fa5de7f73beaf253d4ead33ce2c42e00769dea8d2326f30ecca117f6c5770b024334b171a9c246999703961aea0cd6ad28ad2cc88f27712d75e125278bcc9fe9e3672662ecf5cbcb99c7e3ed8bbef0a5c1f4c0a9e9917c221a1e7509a34e9ff1deae7c4c1068e6aa1d8fe930441c6aff41281d85974afce13c6ca2739ed3f3ed357c1e2c7b3455989c44dcba10c14761e994492bfb62f85a75be7a3b6b63b2e7a6e9071dab876f387375248a28b17152ab45be132acfaafa66b795ae41211c919221e1c32e393db0ffd897235ee63c4f2a6f781288bd51c749923b3b5cc856020a5e6da069aab8b53fb23812f0c227a6cba906a53789512dfa23d2308c047cae398fe6130fc7d01d6a3574d83b7b2e903b538bb0672ea3773cba6dd4b5705f8c6a1d74d1ee5f53497dc233e6e8e2d9551ec769a60e2099dc5c4c0
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153560);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/09/28");

  script_cve_id("CVE-2021-34770");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw08884");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ewlc-capwap-rce-LYgj8Kf");
  script_xref(name:"IAVA", value:"2021-A-0441-S");

  script_name(english:"Cisco IOS XE Software for Catalyst 9000 Family Wireless Controllers CAPWAP Remote Code Execution (cisco-sa-ewlc-capwap-rce-LYgj8Kf)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS-XE Software is affected by a vulnerability.

  - A vulnerability in the Control and Provisioning of Wireless Access Points (CAPWAP) protocol processing of
    Cisco IOS XE Software for Cisco Catalyst 9000 Family Wireless Controllers could allow an unauthenticated,
    remote attacker to execute arbitrary code with administrative privileges or cause a denial of service
    (DoS) condition on an affected device. The vulnerability is due to a logic error that occurs during the
    validation of CAPWAP packets. An attacker could exploit this vulnerability by sending a crafted CAPWAP
    packet to an affected device. A successful exploit could allow the attacker to execute arbitrary code with
    administrative privileges or cause the affected device to crash and reload, resulting in a DoS condition.
    (CVE-2021-34770)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ewlc-capwap-rce-LYgj8Kf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f8bccb0c");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74581");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw08884");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvw08884");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-34770");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(122);

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
  '17.3.1'
);

var reporting = make_array(
  'port' , product_info['port'],
  'severity' , SECURITY_HOLE,
  'bug_id'   , 'CSCvw08884',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
