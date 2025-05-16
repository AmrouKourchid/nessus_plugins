#TRUSTED 20a9efd614dc87e0a557ae9975c2e3e8e33394de9e13f80e1c85cc526d77d166568760a7284c3292792aba39986135e1c633b54bfa95675e5544327f7c0daa42abaa0e65e363cab0942a9ea336e36bee82b4da4a9f05e6983a7f6c9bdaffe3340a7264485ee1891a131d5833a628024b5d5524050419b624bd14857dfcea4edf583bf0aa831cfd4ee47775e9a5a1e016db5c8752123b8a1c93518b7a17e90eb3c115f6d9f5901d970e02a4cb2fb5e295a4293fa578799079755cd146bf474add0649f1b86a51d04a08b6263c3e2b9b974c6aa96038f5e708fdda471f13455b64be96f6e730f0712564ce167f40e0ae231a99e0571752907352e8a8906a293602b90a11d379c79939105e0128375ddf5fd696d0467ae73d43d9f8cf443362802da4f838f5c6c25a489fbd61f9d51e5d18526274a17842a1db830d67fbdb488a8182489f92516e8aa8197460dff30d662caaab80b0a2c4ffbb7daf2911606a04f6fd54b1b9be47d02d8b4a5e1b7651e2aa5cfd83d07533339b42b07aaad2e34868ce71178ca9393307a541c666991cdf97b50056a562ab71cb93b4fba9177d3ed6abc1724876aefcc65b18011d9879515d0d3e95c4b617fb5197df52937954ce5919314e8c01b3c56858f5c63e867be3aea3997b300c62ea9adf40757fdf760d89d7a31d6fab6f9547e8262d9288e19d5351483ab5c570fa20639a92eb31b60e80
#TRUST-RSA-SHA256 32f6436be860c0dab5d17c2a95853fbb7c5c7194f53de7b8a1d226362729320165914ed2cebe506c698d3170d63729cb956ea99ac63bc62c6ec6cecb97ca73544b86c8676c6d79b83cbf7335f8ece84cecd82c9b6d5324642121fd3cf68ac46b628540daf8cb8940e8e4eb96a84fb398225c80fbbddbcd9cc4e06e7b84c833cf2cac36c1b4e8dc4c3bdf40b24ef75d90ca5eafbf26b6bad70c5fe638bee0d0b030ea64c0be8c396b19b9d188f109e4a24e22e7cee756bf7b350fb3e3ac1b687e0e800b81504d7979dd0930d47cf13e526c9485132c24026fac733e722da04b353c1ad291088cc2140a7942feeba74cf71f80e6ca337ea18f7e1b29c8f5c4b04e1e25feb66d16112b33a6e75d047c6b285c7d1fc3dbc316e43502e123f26547b7ddda5b7ce3ff02e5fe8fcb394139d46c9f4ab69fd9103f377054da3d6d02b4b8c2961044af85954a8a83f6cf45bd8437eb117fa3c431a5a127b0c57d19c0815e438f2dff51fe33ebb16f9944c2604d7d654078386d3fa56e2ae3e700427599411dcba6cc7b3d490c5ed28988f60bf44727b0f6a48c4d4443c432806a8017cc164cfb04d9eab3c85e840a94b90f48a2dc572cf8e5f7eaef46fde0d13414f25a75f80e6ad946e9e2e77582d02f910687f7a7caa6f8190f3d34d1f9adcf9c3a7b7d4c2d604e65dc93d36966d9625005ad1f4f41626550075c0ae9a79c4ee7c13a79
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(127900);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2019-1910", "CVE-2019-1918");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvp49076");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvp90854");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190807-iosxr-isis-dos-1910");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190807-iosxr-isis-dos-1918");

  script_name(english:"Cisco IOS XR Software Intermediate System-to-Intermediate System Denial of Service Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XR Software is affected by multiple vulnerabilities:

  - A vulnerability in the implementation of the Intermediate System-to-Intermediate System (IS-IS)
  routing protocol functionality in Cisco IOS XR Software could allow an unauthenticated attacker
  who is in the same IS-IS area to cause a denial of service (DoS) condition. The vulnerability is
  due to incorrect processing of crafted IS-IS link-state protocol data units (PDUs).
  An attacker could exploit this vulnerability by sending a crafted link-state PDU to an affected
  system to be processed. A successful exploit could allow the attacker to cause all routers within
  the IS-IS area to unexpectedly restart the IS-IS process, resulting in a DoS condition. This
  vulnerability affects Cisco devices if they are running a vulnerable release of Cisco IOS XR
  Software earlier than Release 6.6.3 and are configured with the IS-IS routing protocol. Cisco has
  confirmed that this vulnerability affects both Cisco IOS XR 32-bit Software and Cisco IOS XR 64-bit
  Software. (CVE-2019-1910)

  - A vulnerability in the implementation of Intermediate System-to-Intermediate System (IS-IS)
  routing protocol functionality in Cisco IOS XR Software could allow an unauthenticated attacker
  who is in the same IS-IS area to cause a denial of service (DoS) condition. The vulnerability is
  due to incorrect processing of IS-IS link-state protocol data units (PDUs).
  An attacker could exploit this vulnerability by sending specific link-state PDUs to an affected
  system to be processed. A successful exploit could allow the attacker to cause incorrect calculations
  used in the weighted remote shared risk link groups (SRLG) or in the IGP Flexible Algorithm. It
  could also cause tracebacks to the logs or potentially cause the receiving device to crash the IS-IS
  process, resulting in a DoS condition. (CVE-2019-1918)

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190807-iosxr-isis-dos-1910
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6e181e06");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190807-iosxr-isis-dos-1918
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9cf9e486");
  # https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvp49076
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?22433b62");
  # https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvp90854
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ec503ab3");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvp49076 and CSCvp90854");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1918");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/16");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version", "Settings/ParanoidReport");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XR');
if (report_paranoia < 2) audit(AUDIT_PARANOID);

vuln_ranges = [
   {'min_ver' : '0.0',  'fix_ver' : '6.6.3'}
];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
'port'     , product_info['port'],
'severity' , SECURITY_WARNING,
'version'  , product_info['version'],
'bug_id'   , 'CSCvp49076 and CSCvp90854'
);

cisco::check_and_report(
    product_info:product_info,
    workarounds:workarounds,
    workaround_params:workaround_params,
    reporting:reporting,
    vuln_ranges:vuln_ranges
  );
