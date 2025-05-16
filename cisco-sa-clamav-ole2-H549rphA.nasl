#TRUSTED 564bdee6b67baee3d8b73a6cbd7bc273dffee2e9cf64cbdf9df7efaac31f2d7b0659acdab19f0f9c3f8b759f9525d2bd58cb6d6dc5535430f7e306e415df84d790501f72fe4a8240795046930ee35120266cfec611bc1f6b9b57880a3e3ca9aa85a9631b30fd2b9cc720caec7392bc027ca4c75f192ba98d249f748af417c3e4a8354da7dc0bab804c25fc1bf5010b46b8bdde4b8a5dda2a48caf67bbd6287e8d8ab88772d543fa815672ee87eaba27269bb30e61cb10cf269a9790e58f1bcb76e98de8f9c86a29720b23795b611c4d4f573a3641696edd45a5c0240966078287098a7862762ff1e491af8412207554cd57b77ca83e7f1235312a0b65228f77babdaa0aaf29a95855309cd03eecb0e7d9a9a9fbb795f5e0aad0fe6ad9094b2cc30dc81e6260aad6c28c78266a02a85396e46e49c63cfd2e203ae609f1c2c1d89a1b55a4b6dc8d07427c6513ae64d3ad9291a328ddd7083d470b3138472563c66ee38399585e022cc8fa4dea3adc10bdf65a6ab0260cc6712ce756ddcac2a4d289c7fa4d9506cedddb41d7321c53c1060b00bb21f6dac741c99342d73e2545d35df0f8d1eace21ad42af58fd8af6cd895511c30db583cad3cb514987c70496c1b6b90019bf7b302696049641c3259b84cc54bfc04049d4331b433b303b55d7614984e13fc051ca695d3cd3f8a12658a89b790092ea460edd97cfe281a77b608b9
#TRUST-RSA-SHA256 6c54dac1f0ed1e10a3becdef8fda069ffda0d3501506bf6877721c470310e8c73daec855dda4150e087425a4bc631b8bd91270bce5cbd95baed68ca2fd3b752536f86bb20627065bb3d940bed44bef4cc926fe93984ed30a73c986d2675de862b4aa95c25905df59a0147cbfab243f272fd330ec4726b3eb8ce05f7334c2298d2eb246ef018d5a50148dacc1de5e2fbf0f0f0d7b341ccd70ba44dd015973e2087fd9628c00c1911f582ed198a6222511f16ee7947539fab0c76bfd8aa32c5a3f0c4577479542c3c81f92f438677a1bf24ab5ba6fcf3e16f266d176664d593fefb41309a3e62415c7efa6043608a65febb141f2ce36b4a5a62dc9be61121d29f8e8ba56f6d6552c5b9b0bf10d02f2b8c4659a3d45663cc540cbc434cc1c744ad0a95e28b6ba350d39fab1b26c5a2966a424cf36845cd10fb8266239cd3260b1c76dd35991e912ba5c48365050a1dcccf68849d4b91e7ae29a1d200741f9fddc88563320d20c775be6f09993e245bbe3aac1e91f2036108a5be05ff52335953e64571c73dfce8c2ed06be35bae55f817618d1e291e5173f284eb63d932f8c5c435aa5997e2734a1195c1c59340cc955cef62e398b2475883e484fd12a8196505b85821ad5c16af0cb6e7ffa3cdb274565cb20211a45bb6ebec1386bdf7d608e4c7271563c1e512d756ef249c678bd1625eb934e41f8921b1384d146d80a4f1361f
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(214849);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/03");

  script_cve_id("CVE-2025-20128");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwm89781");
  script_xref(name:"CISCO-SA", value:"cisco-sa-clamav-ole2-H549rphA");
  script_xref(name:"IAVA", value:"2025-A-0066");

  script_name(english:"Cisco Secure Endpoint ClamAV OLE2 File Format Decryption DoS (cisco-sa-clamav-ole2-H549rphA)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Secure Endpoint Connector for ClamAV is affected by a
vulnerability.

  - A vulnerability in the Object Linking and Embedding 2 (OLE2) decryption routine of ClamAV could allow an
    unauthenticated, remote attacker to cause a denial of service (DoS) condition on an affected device. This
    vulnerability is due to an integer underflow in a bounds check that allows for a heap buffer overflow
    read. An attacker could exploit this vulnerability by submitting a crafted file containing OLE2 content to
    be scanned by ClamAV on an affected device. A successful exploit could allow the attacker to terminate the
    ClamAV scanning process, resulting in a DoS condition on the affected software. For a description of this
    vulnerability, see the . Cisco has released software updates that address this vulnerability. There are no
    workarounds that address this vulnerability. (CVE-2025-20128)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-clamav-ole2-H549rphA
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?78f287fd");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwm89781");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwm89781");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-20128");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(122);

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/01/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/01/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:secure_endpoint");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_secure_endpoint_win_installed.nbin");
  script_require_keys("installed_sw/Cisco Secure Endpoint", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Cisco Secure Endpoint', win_local:TRUE);

var constraints = [
  { 'min_version' : '0.0',  'fixed_version' : '7.5.20' },
  { 'min_version' : '8.0',  'fixed_version' : '8.4.3' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
