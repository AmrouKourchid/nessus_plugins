#TRUSTED 4ec4b24acfd99803dc360142ed5807fc60ab0373305869b66cf0490e8a496a584f1f28f664c636592ac804ec2f6750955a7b8870037728a05e15311e108677f41a5717439138957db060e615b99e053c3865e4511a8a28c5eddcf01815f81eb0f8d680e891ca1d0557ad4b2090479defff1677e8b624cd30cb475472c3023497ac76924b3964bf3287aa4f7b2dfe51a253b46e1de0ced5f2e8db62276e14dc2f185f10032e45006027671815221eeae17d844b12d39a11330f0d7756d69edbe1ba2c6a337cdc022282f6eb9225379cbde35ad52d3c83231054e8589a6d9d9668146fece8d4863d2a664ef172e91e0cf0e0d53f265877567396b1ff794928eeebc261dee24d7caa9155c5a31956b08f159b4057ef72cc7dd4f29637d43f4d9aceaf6dd1db064a2dd9171ac174bfc76ee883ef46f015b43a89db5cfb1f2d53b0395d8ad87be612c4d0b6b8861b31890e04d97777c426916dd6d837669919082124691f96358465e1b79985b61fa8e49b57440bb3d502c355a5dfe344c299b98b888a4eabc3912bd90389a620327b48ea1d669bc5168c2e751a7573753220d1749c669ca5bd8acd563828124e06904fe6668bc9ac45d954050165586a09aab0d42fa90db5817803ca7239a93344ddb6802139c09a2bf5ca26fd59fbd1934608c0097361da4cefd0b7f7a08b9cc8421753dfed7cd25155d6c8b8d3ae8ccd4f116ead
#TRUST-RSA-SHA256 9e98aab6ce275e50a5ceddc93cfe20d8046b5f8b04163e21f5bdcabb9d9897c198c6a0438540e8a1e56564da43e3fd3409a5cd872754216a318b261eb9b4acb093b1140c73e53dd3e2f14f5ca77d438c341c4c73e1ff540ef7b49fea82489ad2d2afadb895c05f38ef27ca70085fa38161d67a865ad5131453029187d057a89c6f8bc5d088dd2e29421cbf18efcbb43a86f872dc41a6929e173476e7a6356ae57872c743e0d0dac5007950ef6325443656a19db7d0ba012f769540799a0e26bc52b98e70ad95ab614520e754d7175994fbeff8b4e1834a99fe9326d590e140c90d4572c3e501df18301965816b2aab4b49da88988107e0ae6fd789b33f370dea0a441d8b2fe22bc27874fb963b556192fd0e6cddab2f2cc85ff6194f2be198a7247489bc194eba966bc2b4f2c9093d443831d19cbb892f0caedf1f2aaa0bbd1c0515fbbf5c47b795b86404c778daa0ab05d3cac53357a60607e01ef2ff64e2c610ee460f4a10d44a177818f43ac367fbfeefad84b8dd86ff8a29016eae90ff2b059752d4dcd4010c352856ed7f0fae3be1d69181f9aa0760e48dcec0851821b3a0f610ba82eab0e1e1d9b200c3268661e4be39e8e277079b53f1495bd864e3af8b7d68dfa6d799c71e505d8e088fb3159c00dc345c6a8018fc2244eb1e0c2cb98eca8f871eea3d47c4ce3fa839b9a81eff45fd971acd34e7585c2d31494c557a
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(207233);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/06");

  script_cve_id("CVE-2024-20304");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwk63828");
  script_xref(name:"CISCO-SA", value:"cisco-sa-pak-mem-exhst-3ke9FeFy");
  script_xref(name:"IAVA", value:"2024-A-0573-S");

  script_name(english:"Cisco IOS XR Software UDP Packet Memory Exhaustion (cisco-sa-pak-mem-exhst-3ke9FeFy)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XR is affected by a vulnerability.

  - A vulnerability in the multicast traceroute version 2 (Mtrace2) feature of Cisco IOS XR Software could
    allow an unauthenticated, remote attacker to exhaust the UDP packet memory of an affected device. This
    vulnerability exists because the Mtrace2 code does not properly handle packet memory. An attacker could
    exploit this vulnerability by sending crafted packets to an affected device. A successful exploit could
    allow the attacker to exhaust the incoming UDP packet memory. The affected device would not be able to
    process higher-level UDP-based protocols packets, possibly causing a denial of service (DoS) condition.
    Note: This vulnerability can be exploited using IPv4 or IPv6. (CVE-2024-20304)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-pak-mem-exhst-3ke9FeFy
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?328e8a07");
  # https://sec.cloudapps.cisco.com/security/center/viewErp.x?alertId=ERP-75416
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a636b5a5");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwk63828");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwk63828");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20304");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(401);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/09/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/13");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version", "Settings/ParanoidReport");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

var product_info = cisco::get_product_info(name:'Cisco IOS XR');

var model = toupper(product_info.model);
var smus;

if ('IOSXRWBD' >< model)
{
    smus['7.7.2'] = 'CSCwm05729';
    smus['7.11.2'] = 'CSCwm05729';
}

if ('NCS5500' >< model)
{
    smus['7.11.2'] = 'CSCwm05729';
}

if (model =~ "8[0-9]{3}")
{
    smus['24.1.2'] = 'CSCwm05729';
}

var vuln_ranges = [
  { 'min_ver' : '7.7', 'fix_ver' : '7.11.21', 'fixed_display' : 'See vendor advisory'},
  { 'min_ver' : '24.1', 'fix_ver' : '24.2.2', 'fixed_display' : 'See vendor advisory' }
];


var reporting = make_array(
  'port'    , product_info['port'],
  'severity', SECURITY_HOLE,
  'version' , product_info['version'],
  'bug_id'  , 'CSCwk63828'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  smus:smus
);
