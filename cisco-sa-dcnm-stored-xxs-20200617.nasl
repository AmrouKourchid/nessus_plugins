#TRUSTED 8ef52078e2c8570a28fd8db554504d7ab92a17a0cb455122696a325c12b154496ebcc1541998b645dded4dc04e4f681db3046e7c6de45dfc1cedf10038f2b79e15207c788b4dfde274d08934dbc0c45c857246c6eb31b3210b319630b1ec0e57fde7286c82f41ddb5098075604493125d69029d24f23b7362662c5ada103666829a67e117396bdb4b3ce4f71ee07911c420309ad1c593abe7cfeedae692964e7130d0336da4346120d971730c3707f6bb53181b5bdea975ae511aa46b8db0cf2b179f22bbb314013ce9f3f231caa8408ff928404b37966e2c6a481d98927b11ce2ec600ced3e2f8b3043301e688f1d5b10297735e574daa92b1ae978fd9288727dc14f78bc30606fca9c085a91fb2785ff7a433f2c6c040aac024158f49e0230155cf1089cd236ef433657a78776aa0390d06dc014dee22e57acfcff80a03453e90eabff0c93359d4d21a6a7d3a5ada7cfd277ae0df0d9107d0a8cb165118f3a909dc88862fef8a7e48164fb6b6d17a0b2333d1f50584e9e1726475425f47891c731a10e94b1eef46fd132e789a20058317059a21ade1051be1a91cd792899649fbe826fccf8f51dd030711463ac32aaa52b6bf55615be0a1cb13b1f948b05f01bdf7aca0f76fbb3180604f77fe4516b757dff54ee6ee00338e36e683153ec94f5caadf8242481ea83e96c98ccb357c15023e3c9c5d5641c336058d08f6e168f
#TRUST-RSA-SHA256 76b1944743a263248effb502d5756314b39601706c7134908ceb426958f782224fa857f137283b13e5123277b48d8430a36677ba098bc6775063ad5110b1dae769cc1d260ab211aee4cad568b7ae2393debb64aa026392b0cd6163a0ee3dc64b74fc2a14cc83bd761b63d64be873a31b6828ec17e8c5947f607fc2eef56c5c5993d72ca0624efe13339948c4841200b9be28becacc9f320e2e1bd61cb4143e3d6ecf15c235af62a468f8b1f26fa3287b4bef7948bfaef801e5f99412d22a8ff2770fafaae5afb6d459b791496903515865f0985903b1a7a4b9ef29892503925ef91367286a17a16a204460839e56861c07fda2f6d33419d6a1f6b7b90bd89d91afc067b3dd0b6b9c6d04b3b5815046ed2ab11409c84cce7c73e18f69c0c2a1aab737cbbf6eb86712b50e321031b4d2acb1a977065e1f907c439cd24c8345a1041a1145ea7a2068ec7736a3201f72303fa92148cf4a3203a4d389d67e6a664eb6b003365c42d2ecd868d8c44e97d5300424ce9b2de692a8badaaaca3f58847b01324b84fc3daad1d9c5caee760a65bc66511b73f2027a74564c2cbacc7e2e19b9ca34dd4289ee2f52fd8f3f58f2d0f26f1486248ad66a633c6d74f86d0ddaf88d252ef07fb83b1673d4b009e448d22f0c49d0b2530916ebfcf8e8bed4e57e865058dd12e0a6c940f753bf83c3c0471de0fb4f8fc8923779839dfb1df5015a4b4c
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(137850);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/04");

  script_cve_id("CVE-2020-3354", "CVE-2020-3355", "CVE-2020-3356");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt05178");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt10966");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt10970");
  script_xref(name:"CISCO-SA", value:"cisco-sa-dcnm-stored-xss-VyE4bNAh");
  script_xref(name:"CISCO-SA", value:"cisco-sa-dcnm-stored-xss-yJyqBJGU");
  script_xref(name:"CISCO-SA", value:"cisco-sa-dcnm-stored-xss-eUyGPqxm");
  script_xref(name:"IAVA", value:"2020-A-0279-S");

  script_name(english:"Cisco Data Center Network Manager Multiple Stored Cross-Site Scripting Vulnerablities (June 2020)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A stored cross-site scripting (XSS) vulnerabilities exists in web-based management interface of Cisco Data Center
Network Manager (DCNM) due to improper validation of user-supplied input before returning it to users. An
unauthenticated, remote attacker, administrative credentials can exploit this, by convincing a user to click a
specially crafted URL, to execute arbitrary script code in a user's browser session.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-dcnm-stored-xss-eUyGPqxm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?37e25ad3");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-dcnm-stored-xss-VyE4bNAh
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bb1a5d8b");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-dcnm-stored-xss-yJyqBJGU
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bbe408e0");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt05178");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt10966");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt10970");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvt05178, CSCvt10966, CSCvt10970");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3356");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/26");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:data_center_network_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_prime_dcnm_installed_win.nasl", "cisco_prime_dcnm_installed_linux.nasl", "cisco_prime_dcnm_web_detect.nasl");
  script_require_ports("installed_sw/Cisco Prime DCNM", "installed_sw/cisco_dcnm_web");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

app_info = vcf::cisco_dcnm_web::get_app_info();
vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  { 'max_version' : '11.3.1.0', 'fixed_display' : 'Please see advisory' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  flags:{xss:TRUE}
);
