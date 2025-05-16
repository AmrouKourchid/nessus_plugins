#TRUSTED 81faef9d21df7bb571d308491323d16a1fc54e1b2c9f41f83ae08d44c83893aeb66f8467f67a6a81646863e06bac138fbe171c9e1180def6d40f9223749a0f6f710cdc9372ec1c394757ee78369e3441896439cc0c9ae0dab7908ba64991dd74f5ed9b4f614ee92ddb52c6b2fa903c4ef4f51cb4e705743f5f0b8a81885a94a4eb4c4764a593a05864205a03b57cb641d36c0662a865bc0d1abe879b2126b9500529d1188ade4bee55d137a43489357c3d9d62c4a51812e223eb64b74c3cabc1aaa81f253a432f788b4dc1ed12975c96f95bba794424a17dee28719545ab18c7d4b10cd7ac780e0c5c43f4f45405c14c8ec0b257167031b9eb2ee19b8e077a6138a2c50f798cc7108be9c791adb59986ebcb5a5acdeb68eefce6f6d07ec3e37ba28881592a646b36911ffd497fcf8cdb6acfa3f1c686fdccb9b8e862f12adfed139bca071f8267599ab94ddc0e49177938e3727f6025ecbc266265204ecc63f8cd44aa9bd8827ffceb38a0b8c559eec73184c6b8489b725d73f73726815e4cbe90bb5b98fbc9fd3c50f2c01ba2bb86a4da418cfc4482e4ffcc971e9ff4260fd1c8650359e034d78cd89e23bc3f6fc79290855b32c3c102d44c55ed67a16effb861750c2d29bfe19d64a6449cf85249a03876ff101f876eaf389cb6a64336241cd38319a0d50bd2caf4bdccb2c0236d3fd7e62624ee0fb043a303187b11ea8334
#TRUST-RSA-SHA256 61f1f7fb764bb231bca71196284fff2a5ccc831636254e6db0e753be0b1dc591b2eb5a8eb3ea5c211a3bfdebe0286d37ee10a8bf7c1a879d13f45c9711675078b0893ffd61f9cd97ecbd5524356154f90d08905c0cd948409929402165513af138b10dd8f1a171700eff1c67691d076878d4865a4dcfe17ffe586d33697b1f44ad25177593d522e2a6332bd83ad07b1b9f52cac5d9dbf364a8104c67c02c4590d854b24826cde38a014d3a1836204d7133e23c521ffdaf7d9dd7b9bddbc10f5b5b3e75851f7d83e052e78938fa832545c5f641bb801cac1061447809cb6d42d0373c48112d7d4df5b7279a7bfc7648091b326cab41c8e0e6b73ee468ea30c545ff2679a2e6c9045659c5a33205e36cf15feb2fba907177ca46a0bdf88f5f1706b2aba3fa39e1f92050906f1df7156dc316c772a07c619d61ee4a2f91c2b1354226aac03b74d0076a8cc3760ea8d6a89a4c872449369eb80f045c66bafccc9ebbfb1e263192cc91097d90210257a62b14d2bb0a06e72e2e91ea437dd2b849edd87b59385a5d0c04c2ddfebe7144a2bd29b14a877ffde75fa203454b0f590f84059ce214eac60989936c7c8bbd08470b7ec12d5ec47b8ce4af56a7957aca9058e31341460881edfe3b93128e01809a84603c5851ced699ae2b64a0955229f402d1cf26e804674a75b150d7b1b84caa076870890bcf2625e388c4c21bf814f5ffe4
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148250);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/08");

  script_cve_id("CVE-2021-1288", "CVE-2021-1313");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuy67256");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuz39742");
  script_xref(name:"CISCO-SA", value:"cisco-sa-iosxr-dos-WwDdghs2");

  script_name(english:"Cisco IOS XR Software Enf Broker DoS (cisco-sa-iosxr-dos-WwDdghs2)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, IOS-XR is affected by multiple denial of service vulnerabilities:

  - A denial of service vulnerability exists in Cisco IOS XR due to a logic error that occurs when an affected
    device processes Telnet protocol packets. An unauthenticated, remote attacker can exploit this, by sending
    specific streams of packets to an affected device, to cause the enf_broker process to crash, which could
    lead to system instability and the inability to process or forward traffic through the device.
    (CVE-2021-1288)

  - A denial of service vulnerability exists in Cisco IOS XR due to improper resource allocation when
    processing either ICMP or Telnet packets. An unauthenticated, remote attacker can exploit this, by sending
    specific streams of packets to an affected device, to cause the enf_broker process to leak system memory,
    which could cause the enf_broker process to crash, which could lead to system instability and the
    inability to process or forward traffic through the device. (CVE-2021-1313)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxr-dos-WwDdghs2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?62a59336");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuy67256");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuz39742");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCuy67256 and CSCuz39742.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1313");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/31");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl", "cisco_enum_smu.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version", "Settings/ParanoidReport");

  exit(0);
}

include('ccf.inc');

# Cannot cleanly check for mitigations
if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

product_info = cisco::get_product_info(name:'Cisco IOS XR');

model = toupper(product_info['model']);
if (empty_or_null(model))
  model = toupper(get_kb_item('CISCO/model'));
if (isnull(model))
  model = '';

smu_bid = 'CSCuy67256';

if ('ASR9K-PX' >< model)
{
  smus['5.1.3'] = smu_bid;
  smus['5.3.2'] = smu_bid;
  smus['5.3.3'] = smu_bid;
}
if ('CRS-PX' >< model)
  smus['5.3.3'] = smu_bid;

vuln_ranges = [
  {'min_ver' : '5.0', 'fix_ver' : '5.2.6'},
  {'min_ver' : '5.3', 'fix_ver' : '5.3.4'},
  {'min_ver' : '6.0', 'fix_ver' : '6.0.2'}
];

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_HOLE,
  'bug_id'   , 'CSCuy67256, CSCuz39742',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  smus:smus
);
