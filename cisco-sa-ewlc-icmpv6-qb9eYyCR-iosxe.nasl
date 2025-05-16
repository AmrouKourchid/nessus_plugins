#TRUSTED 4ab9f98ffc2159b067acb53a98300b68236ff36a87ce8df6a143d6eefda77a4f10664dc192411a4e4d6760b115f7e20f944c0046f5a026512af04f6fa0f42d4264058150c5b3f73e821c77e34857c64fb3c9e331db5d5bd32a6a257ed07357ffcc1319afe7f6c87e2bcbafba95bb35a0c4c966663fe2074d54c87b70c9399ee798693d36de7a3876d39b68a305ca95030bc85fd3e307f25d971240b306c44acb447d1071ac4f191436f74993cb226c6b6ffa7d2939bd96a236e7fd671bcc99c71ca47e7bf55ff905bdd35d4f8758c5209f31b56ea4f2ba6840b24026d6b0bd0faa39067f20387e441e4293d175f4431eeaba410069cc674981073ac87563bc1fe161761d2891cc082db5a992d57a62a2ed00d830eff19de1b3dccf75e462d104e42c8a375343cd1e8a482243f576d6bbe328005e37da7c2df84a89ab7a2ac8a6fce929d5b0a32b748ce2ae0ae4614e615b0df603d5120ea72ab2157f174d81a22a8fa9ae3b9bb5f5c80efa3cc372bd1d129ce4a378529cef84aefc419242cfb2edf13577a741059b686bd5a50f619a9024fa390883e9a0fb3895f25a5b469f71e1065f46a0d9a4bc584602faccfa1ce3f9a8e01f70ea2e91099537bf179f7214a5c97e01cf2e0dbb3412c490f0d237480aad9ff8ed4ca993dc5b448ed7ead47e27a01359251ff9cf05b6ac2d8347df7c0e3b247ee726555645224293848e9324
#TRUST-RSA-SHA256 a96ba7a4033bb050c13400ce49563cc9c9c22a697ff3fa7d3671f450d37a2c3de79ba30dc8cefc6f02e586d4f7cb144a5d8b04ad754afc28b9d09e4bf65fb2c4f63de914dfd9ab87fc42f8866979d47f77ce6a76af33410532f616e731acce85357dca599593e0d8bdbd78caaa9357932cf5738b64a60aeb7ef24f56f28e05168562d4deb9ad26cd22a14ed886828e8eebe90e968b0f8ad15239b9448bbe6afc0862d1facc846c0c1656b5fce727b0bcf04106d22bc41102eb3e12a5f8c3ba87be29943b73f3ae83beae60979e3dd6340290b0c1b2dd5ddeaccfdd4e8532ccfdb3abe2137e6f7d7c285b13d915cd04989091c50be6f1e1118b4ccc30caa84c4e02917dbfafc51b85b3939e12bcd0467075e041dd3f9db776c4deb27edb0ed113c63a5e5591ebbe3c28a74a992a6c5dee9fa8fd806075683e14474718d4c82bcea36375776561be20ce828064aa931283f3eb00a9ef591be49e086462bf9cdcf4c52e16d576a4dd3373a8131c11b7631332680046d24fc4d010a2261ecd4d93f136da886e86852ac62eab6880b87f66655335cfd727b8b50d7671bba53f09c23d533f0cd61e176f3b05557c625b2f7bf0943526470325c7765429114972a29322a9d455d668631658fee24f22215aa42eba7cc5cb448865723aaceca03106eaeb59f1cff75f86bd9f7f2898d605999cdad1341d776cc60a21ef237b05eba676d7
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(144197);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2020-3418");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr07309");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ewlc-icmpv6-qb9eYyCR");
  script_xref(name:"IAVA", value:"2020-A-0439-S");

  script_name(english:"Cisco IOS XE Software Wireless Controller for the Catalyst 9000 Family Improper Access Control (cisco-sa-ewlc-icmpv6-qb9eYyCR)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Wireless Controller Software for Cisco Catalyst 9000 Family
Routers is affected by an improper access control vulnerability due to an incomplete access control list (ACL) being
applied prior to RUN state. An attacker could exploit this vulnerability by connecting to the associated service set
identifier (SSID) and sending ICMPv6 traffic. A successful exploit could allow the attacker to send ICMPv6 traffic
prior to RUN state. 

Please see the included Cisco BID and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ewlc-icmpv6-qb9eYyCR
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7a00821e");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr07309");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvr07309");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3418");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(284);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/14");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/IOS-XE/Model");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

model = product_info['model'];
device_model = get_kb_item_or_exit('Host/Cisco/device_model');

# Affects Cisco Catalyst 9100, 9300, 9400, 9500, 9800
if ('cat' >!< tolower(device_model) || (model !~ '9[13458][0-9][0-9]'))
  audit(AUDIT_HOST_NOT, 'affected');

vuln_versions = make_list(
  '16.11.1',
  '16.11.1a',
  '16.11.1b',
  '16.11.1c',
  '16.12.1',
  '16.12.1s',
  '16.12.1t',
  '16.12.2s',
  '16.12.2t',
  '17.1.1'
);

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_NOTE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvr07309',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:vuln_versions
);
