#TRUSTED 76f1043174db0f151ba3aa7dc65ed166c0b6283b8fb62ea57a9f4de713d7131352a4dca57df0312e5de822309cba8a682723b0f80ed403bef261948c7d491bac18b24e377901d5e86c25f089a91aecc701b3f6cf834d5f6159553b63644e5842236a567bb1425d4e565781ece9cb2d6816f52c48ed4eb156cc8a4371049564c2359d08858ec6e138e6a84b6816de5a06b56b712175bbc2a783296e9cf4cd4aff179c981045cd6badd85490711e246e13a422d13399b7e4df2e27377e369418d36f2b3d942d4f81e8a0d644be1581bb646eed3b66d70fa2b26467ba45e71a271226989acacc8e00ccc41518a2258ee7b5ff89a02da33778602b5f621d78b6bf05a1d6faafa79c350ab04f90640bb3ca54b94c79aa52c78f4edc5cba0f93b2cbfa103263932554b1bde8d7b678aabdb7dbd6f2cd0a4054a54517520f1be9dcfffbdb3481515589412c7816aecf6464d6532ea9ccd1bdb4db10dd624ce3725531440131bf8cddefaea244d1dfde207dd03a02d26bbc01b26f10cacebba640a557ed9daab5269d8691a76b717c7d81c1eb0757eb2eaadf7eb45a861522afef360691f8e9f35281cb60d9a01e63062fbd064305a5ec4ad5de9688c3619e2bdab597077f9a44271ae9a39f82cb0d09c083d49a74a6d51d758e79dd72ea2c3a9476582b673efe70b86cb4a6a2c385bae8f16cbe0f66cc5867cdae6c4a3e7fb2021a1b57
#TRUST-RSA-SHA256 301f971ae0e784407675dbb90b5a695fb41ad711cf133ccd2038a20b9c4b8fa0cc74c0b330daa3c165b4d2b73eaa6abfb7a6d8f55b3d979e2c6d238aff0aa83ed0eab3006576f9ce26922f999ca767d3cf3692136b12d5245cb5322ab86b116f2c2db73c191390c17e4b2849ab831940e8f7b3da13d13ababd3b730df7c538b9cfdedc09073a8c4a111a6c6345aba581d59f2d9c84f737156cd49acc9736c73cf6a289a9911817e4e6650b236e5c929cc82bdcfad950a53e1592481a97cede18d738ed0fe48571d872cead0a0050ade67f9927c0b7a8af0c20ceb9162bfa4542b786218c6d073584cb049891421d84606cde4eb117a433130d9a9ba1adb5dd2060807158186b79cfa0758218964c76013051bbaff43924bd918952e75d38176d6b50d37dee064132c94885cd060585833711a484c796a7405138e3d5d41cca476788b2e6e94e1805f12eaa22c09e468239af2dd1421655517ef6142ec4d807d993e5ae668e2d723956aab25241e5467523c41946276867e37181265476bda76c63e6b1c7ec5fc6b3a96c2580ff889f7215d2745da3c17ce0c9b2dd58317ebe2ecebe8ed8dd5038a82164a72beab696e0202632e5a8d27bfd7098348f9f0ad4c4a87129fd46ccf371085a3bea411f17bda6457c5287937538effba1e8b176cbdb125257303bcdb44e2bed912792cc325b6049ecbc4f5fa5996729c2d373297011
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(169452);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/09/28");

  script_cve_id("CVE-2021-1624");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvx37176");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvx75321");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ratenat-pYVLA7wM");
  script_xref(name:"IAVA", value:"2021-A-0441-S");

  script_name(english:"Cisco IOS XE Software Rate Limiting Network Address Translation DoS (cisco-sa-ratenat-pYVLA7wM) Unpatched Commands");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS-XE Software is affected by a vulnerability.

  - A vulnerability in the Rate Limiting Network Address Translation (NAT) feature of Cisco IOS XE Software
  could allow an unauthenticated, remote attacker to cause high CPU utilization in the Cisco QuantumFlow
  Processor of an affected device, resulting in a denial of service (DoS) condition. This vulnerability is due
  to mishandling of the rate limiting feature within the QuantumFlow Processor. An attacker could exploit this
  vulnerability by sending large amounts of traffic that would be subject to NAT and rate limiting through an
  affected device. A successful exploit could allow the attacker to cause the QuantumFlow Processor
  utilization to reach 100 percent on the affected device, resulting in a DoS condition. (CVE-2021-1624)

Please see the included Cisco BID and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ratenat-pYVLA7wM
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?82b10ce9");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74581");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvx37176");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvx75321");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvx37176");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1624");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/03");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Settings/ParanoidReport");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

# paranoid because we're not checking versions
if (report_paranoia < 2) audit(AUDIT_PARANOID);

# if the vuln sub-cmd config is found then the host is vulnerable, but no software updates/fixes are available
var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = WORKAROUND_CONFIG['iosxe_max-entries_unpatched'];

var vuln_ranges = [
  {'min_ver' : '0.0', 'fix_ver' : '9999.9999'}  # not really checking versions
];

var reporting = make_array(
  'port'      , product_info['port'],
  'severity'  , SECURITY_WARNING,
  # bug id for this advisory plus the bug id for the unpatched commands
  'bug_id'    , 'CSCvx37176, CSCvx75321',
  'version'   , product_info['version'],
  'cmds'      , make_list('show running-config'),
  'fix'       , 'See vendor advisory'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
