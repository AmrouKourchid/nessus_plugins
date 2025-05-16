#TRUSTED 7633a0cb1c607fb87fdbd4035f384fc59441d5611723ae07c3868b91b3bf90c021150621157ebe6b90d0504c2cbd31d4a7fe7798554756647c4dc09eeefde99fecbbab43c1ae69b08e1b3da12d70a0da6cc35c87de5c69922e990e2e2b4274a909299370130a90709bdf7fde1fe80a361b95495fc577396827557470ba4a32d44966a8aa2f3360c52b30cf65b5834c40dfc5d8ff8a88037ef7d3aa9a318388944b44f136a29470360c59e706a6a488c2d67c8b6469b77c884b83bd0ef7acb53452118c30fc290eb1da4f3d03e194ab1769db0d4cf868d2b38da610d012bc1f9248a28696158e881265e60731808c86a865c0f97d2106bca2d402318e4fd548e29c606caa27a2123d5c656583949e6597466d8ed4c6dde54bf59e4f99c02539b5ec6c060881e1cecff75f10b6a680615c31405b9fd3a4a38ff2eca4083aa91601e6827dd475c4fc7f07ed9d74f9f8987ba9692e64c16c8055d6efd3c1669047b0d1257a8d096102ea361856a18ac7d5026a45b8c521ba25a18e51ddccd4ffd232e96b1b9d0619d7a28c7b9796579860bba0d7ccc73b6d336cc70fbff03986759a1529f2af26a5526e202b8ad38cbfca8426493a50680755f1c95f24aa6d9883186645cfffdcea7ab0fc6cbb65544795d102b16a256480d59ca08d02eafd0e82a2a3e67087e4c4960f8f3f0ad3f2d91636e0504fea3e7f3cc1967e69045788acb8
#TRUST-RSA-SHA256 7e9ab43612abe31757979bee33eb2830cac8c3deb7245540c0caec8eb448b5a52115175a6c5650642ee4ab8928c5bf6bb2048a3b9c2a7ec3ca8198fb2a5b8572438f50c44848d3763e1d4ea6eea74d33f93a2cf4850d746d3b1c676194ca8d771861cbaa919d8386f18fdd491436746680227ebebd7d9d470cec57e50be822d3899496442d55315c345ab5d4fa79272aa8264d6c739e0791571a3c5fd014b50f310d2694121abb594b47fcf5d26c1354262d81a9bcbcd1d29aa4c75517b886a3de79b88455f4b181594d2ee394d4d1660b36e650177dcabef95caa331d5e1578ed47c2e74f6892ee2c915898df7af9fa4b300bab4f6fa826a190c2bccf33c27dfc50fd7e3a0783087f33ba23a1e24bafba78be05eba9eb9b86de420d315f3765e71c173ccf1d62bcb93892f8af2d3c8ee80efee38520a243438845b34ce1f9fd67df1503eb6b900aa724ecbfeb98127d8a602a9ac4f2e5c2bcd91dfe0f5c84dedde5b859a905cc3cd353f19dd77691900ce3c501e242ebafc1eb7176c4902b4f0ca47c54f4b7c2f2296e1716580dae1bc9d3f1eb7c76867179a33a7547741f4d04d3f667888412b8bb20ed10dd23c3e13bdce7198313d7d3f34cb4969a888066c1f502d80e280a1d9f1b7cedb040fe0b30dc15e7a5ece3641f94181ca0e7ec1f59976d0b52eed2caf162345e931516edd4d2f000f6ce7a9b6901fe6729d6ccca
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(182153);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/10/03");

  script_cve_id("CVE-2023-20176");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwb56120");
  script_xref(name:"CISCO-SA", value:"cisco-sa-click-ap-dos-wdcXkvnQ");
  script_xref(name:"IAVA", value:"2023-A-0512");

  script_name(english:"Cisco Catalyst 9100 Access Points DoS (cisco-sa-click-ap-dos-wdcXkvnQ)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Catalyst 9100 Access Points Denial of Service is affected by a
vulnerability.

  - A vulnerability in the networking component of Cisco access point (AP) software could allow an
    unauthenticated, remote attacker to cause a temporary disruption of service. This vulnerability is due to
    overuse of AP resources. An attacker could exploit this vulnerability by connecting to an AP on an
    affected device as a wireless client and sending a high rate of traffic over an extended period of time. A
    successful exploit could allow the attacker to cause the Datagram TLS (DTLS) session to tear down and
    reset, causing a denial of service (DoS) condition. (CVE-2023-20176)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-click-ap-dos-wdcXkvnQ
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?95003dbe");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwb56120");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwb56120");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20176");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/09/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/09/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/28");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/IOS-XE/Model");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

var model = toupper(product_info.model);

# Vulnerable model list
if ('CATALYST' >!< model || model !~ "9124|9130|9136|9164|9166")
    audit(AUDIT_HOST_NOT, 'affected');

var vuln_ranges = [
  {'min_ver': '0.0','fix_ver': '16.13', 'fixed_display': 'Migrate to a fixed release.'},
  {'min_ver': '17.6','fix_ver': '17.6.6'},
  {'min_ver': '17.7', 'fix_ver': '17.9'}
];

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_HOLE,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCwb56120',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
