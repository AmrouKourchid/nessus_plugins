#TRUSTED 59341e62dec0c8956ad835f8d79cf3c5cd445a365f70366122795a1ba7e99bd413d21cae60803a34678c1dc6ff4fe5dc37b62d49a1e4a0098c524de990e47ff520cceb6b546538f675489bb407d23c0f0ca8613fde33d8ce8bfda150390b72cd4bf49c2b5675527b2eeeb83d076c283e215661e816367314960a512bd1878b51341fa286145ef9670c7a1e1f463b87f89c677ca9357f83bde0f0843ad58c8fdaca07b10ba0c169cc35fdc6b53393d88140b1e18264cf9f1a5814dc8ec152971400d3df44484e08a8d88187766b5efee8660ad7825548336bfd82672521a6510d61bf1236058935877efafe46e80347fb818bdeb5b8e703a1ed092fcf5996df4aab2bdb65206cdfbd57f390b7ef6ea26c4848b0b5101dacd7328db340e270bf8d5802f3bf6fe05695c90db165d3735a18fe70249b18246b1af474754938489b09ecde78047ba50af0a8eaa24267d63df5948b902af4de9c8b6cc55a6931231d824e1c7dbe508aecbc8baa98b2695d5fff5b9f0e369508ccb88cecff18573362e00671f65399403080a114361526645085c3c73f06f47d10b5b3f96b53e9b9e89d41d324b04d804e373eb69231cf176a4b888be2c6150c40ea0b32b065916f89c1df62271b864556344fbc7b1ba02f5caf4b64e7b75f9c0e0dc8799245ce2b92602e92febde77c5c0e905c63ca1e095a24b5015f870c12418e354db39df39b466f
#TRUST-RSA-SHA256 1b7e98e341206be03a81a0aedf48911b564f8f835cccb1d900cb8dd823ec1d8524f6d973380e67ec7c5a29d4b495f270a7ae4f3332d042e6aee38660be27e136e118a16af685048ca47ed192b5361a3c008abab808574a66ae4cde63ca1773a25fa255d5d2da551d70fb96e53434da83968801e480390228c57b73d289e58bd122ab9c52376f049e1d186e417a0365e188c6338a5489ab77526b62af64bd16dced5f03c37ffefb4d0abd88ccd07a28007f684f8fc672a0a267e36a65df6a10437ed0f96a93b8a3be1faf0571f44e17d5bafb6b046d04e24fa877e01013c4fb40896acad92dbc8acd1302df9d51ce66c5e3b128a41cb7cb5bf84cf2d4ce24afecfc02a251ec925c3d489305d68821857216ff33d6f0ceeeebd3b4679c2aae9042b858de842c37057af86fa0a928bafa7ec0c1e1db4e0ec5f804aecfb6c377873eb1fc18780f2fb6e945fa5aa861a4e21da8d6fa0eb4587653b31fba7e58c8c0d1801250bb6e601e150869f3912e8dd973b537adb58cc150c9e4a4a4537062e16a496e62d2274f888489e1d38b8783abc0e8d0d54f3bc805cbc3d8cd5100b6f01f38047393d432a25571ee1432814e6aba07f4cecf9c194074d5a91ad8a6c2aa549b096189924b310da5af9e2c38c6c100cc890d60dcc320a0f7ac3fd30c6c686bd865dcc8b0463e28f4e8e3c03098a501dd4c9de23bdc4fa275e70a19e8670e22
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(133267);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/21");

  script_cve_id("CVE-2018-15428");
  script_bugtraq_id(105944);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvj58445");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20181003-iosxr-dos");

  script_name(english:"Cisco IOS XR Software Border Gateway Protocol DoS (cisco-sa-20181003-iosxr-dos)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XR Software is affected by a denial of service (DoS) vulnerability in
its implementation of the Border Gateway Protocol (BGP). This is due to incorrect processing of certain BGP update
messages. An unauthenticated, remote attacker can exploit this, by sending BGP update messages that include a specific,
malformed attribute to be processed by an affected system. A successful exploit allows an attacker to cause the BGP
process to restart, resulting in a DoS condition.
Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20181003-iosxr-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4dc4cd5a");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj58445");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvj58445");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-15428");
  script_set_attribute(attribute:"cvss3_score_rationale", value:"Scoring adjustsed to align with CVSS 3.1 attack complexity guidance.");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/28");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version", "Settings/ParanoidReport");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

product_info = cisco::get_product_info(name:'Cisco IOS XR');

version_list = make_list(
  '6.0.1',
  '6.0.2',
  '6.1.1',
  '6.1.2',
  '6.1.3',
  '6.1.4',
  '6.2.1',
  '6.2.2',
  '6.2.3',
  '6.4.1'
);

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvj58445'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
