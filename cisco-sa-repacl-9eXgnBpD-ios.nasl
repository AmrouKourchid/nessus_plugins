#TRUSTED 474a506ff65f1b7e722c91c3d14868e62021f019fb0e8935e1601778278dd5718457dd8918c6b111898d2a469a277e26c9a2c98e6967638745e38d46fcd03033b1eadecba2f4d1fa3dccb5c50b4862148ba551468cf30ccbf204f90e8bef4a2f8d8ca70dc56b1191ceb9a05909f4ca8a8a846e924c12279e5f4209ef9a843afa8910b41e54cf456192ff37101c3405ea5676d8e5df450658ee8ca05dee283513c01f9bc751f0f74eaefb20367a18424c8a58cdbfb7934bf05babeaa5aa169380d405a9b03047c875b451acbd0aeca181ffb5b7e1afc9e7b255375fd7641e03ed166f1f6af84eb13783afff3767800cf845c212b311bdfb15dcdb0dd88311a42d868c935baf82b5ba9bedb1ce0a2ad85789097201cb57bf5ab32eddc4a3307240b55f237b3cf046c5bfdf4317c019403862d52fdb871b00b61059f2b590d8fc2bc0894bf52cd1cdc3d90a113bcac9ea0f7d6719d97e508ffd248cb2b2b15700e237593e8d4341509748657f71b5cd2eccc4e23d2abaf95bf9da683ce441184864cb4c352e9bff4cd3cde5cdfb23672038469ca24b68f7ece1fbf87c60deb135fed77a724851d22c2aa8b29ace6fb3e6b0b2a10121c343387e4eb342c5e1d8a2e6d1b584848eb36af192b3433da59834d0a8179d922107d6e1c79999873dbe408e81607eec7edfed66778ebb3e358f75da4c15673318353c4ae4f30f84d1aec5a9
#TRUST-RSA-SHA256 8f712132a8d18c45f150a0dfe56bc70a6cfa8b39035e80037a3f53d95babcf07d94ce66c6b6f977ff71db39199eb1f57724cf0815524de6036d777480e79aa6f2daaeed8833141822aa84cea7ec0d6e0929f843bc844d3ffeb54e8016e10a90236aa33c66920c6bf0153b5e085186e1bcad9345c35309ffeccee6c48d9c04d493de56c916552f7545f23e15d6b128a03faf0e008b93117d71d49c3d67762dafa3de56ea0c4775d5daa710e4802bda0c840993c9110cc8a481e9623a88c4c8b3abd9113714ec46b9d84b602c9677a486637bb5f9afd9d17cdaf9e137b51c5eb456dae18f1ccc899c74c5f74a2fb7c13387dd40f0a01c94948f7e138c0b97bb66a39464ae964910689628460cc4c82f6d8969af681ddc7adf3e9498a5be11ccc02a552fe2797e246c12bfd9dca4429f00599ac0024072c39501e45f817959a29d13fef252e1c61866661b398614b13b5618c806c48eb7c318bccbfbf40e05deb330207fe690443bc9c3732f613b34a66b9681d396323be790170ce3fe0e9c00c06992ee7966fae036067f989a754fb054af1c0097e848f23b3af344c84ee05bf30c77852e83ac92d5ba41b64121c9ab4d6f7c5a6d2ddfb47f150c1fbcdb478a3bfa28f9842c7e3ae8aca7a0d45c2de6027d9235c2087213d7a43f070316a14bda02223f599ebaf1e1a00413b2334e35b64af6f69285909df3cf9661412d5795241
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(216854);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/26");

  script_cve_id("CVE-2024-20465");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwi85609");
  script_xref(name:"CISCO-SA", value:"cisco-sa-repacl-9eXgnBpD");
  script_xref(name:"IAVA", value:"2024-A-0592");

  script_name(english:"Cisco IOS Software on Industrial Ethernet Series Switches Access Control List Bypass (cisco-sa-repacl-9eXgnBpD)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS is affected by a vulnerability.

  - A vulnerability in the access control list (ACL) programming of Cisco IOS Software running on Cisco
    Industrial Ethernet 4000, 4010, and 5000 Series Switches could allow an unauthenticated, remote attacker
    to bypass a configured ACL. This vulnerability is due to the incorrect handling of IPv4 ACLs on switched
    virtual interfaces when an administrator enables and disables Resilient Ethernet Protocol (REP). An
    attacker could exploit this vulnerability by attempting to send traffic through an affected device. A
    successful exploit could allow the attacker to bypass an ACL on the affected device. (CVE-2024-20465)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-repacl-9eXgnBpD
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5d42d553");
  # https://sec.cloudapps.cisco.com/security/center/viewErp.x?alertId=ERP-75169
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e0341eea");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwi85609");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwi85609");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20465");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(284);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/26");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

# This vulnerability becomes exploitable only if the administrator has enabled and disabled REP on an uplink interface.
if (report_paranoia < 2)
  audit(AUDIT_POTENTIAL_VULN);

var product_info = cisco::get_product_info(name:'Cisco IOS');
var model = product_info.model;

if (model !~ "IE-[45][0-9-]{3}")
  audit(AUDIT_HOST_NOT, 'an affected model');

var version_list=make_list(
  '15.2(8)E2',
  '15.2(8)E3',
  '15.2(8)E4',
  '15.2(8)E5'
);

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = WORKAROUND_CONFIG['ipv4_acl_config'];

var reporting = make_array(
  'port'    , product_info['port'],
  'severity', SECURITY_WARNING,
  'version' , product_info['version'],
  'bug_id'  , 'CSCwi85609',
  'cmd'     , 'show running-config | begin ^interface Vlan'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
