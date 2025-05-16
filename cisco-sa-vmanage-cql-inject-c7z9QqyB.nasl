#TRUSTED a1bead4d58d029514ee64b1072338fb146241eb0efe4bef2b6807aa2e23ca8970a402d51759d5454efb1cbb69e317d32604731d179319a561878170ba1ffe4c0eb8fb15390b1eaf4704dde7ee4af28f3e77edca1dd55d7df79be9815c74843b01f2870c20a21b33feb7d141dcc9d8d82c6481c895982aed967675ca21050e7ea0d8839d80268d5c132440e50a6285c9c20651b2b1acf278dea70f824cc9d0d7a0ab6ea8213829d2c9436c7a5121cf474b784eade8854303179748d5a935a1e5322dc4a928640ec385f3a0631f57037eddc051041ae873d2047e231aa9caf0e019d9657b139e43ee641ae1393490a6d268004bf45f28c572533b9ae2fa16e32c107f66073ac8bccf1aba39ece4815ade923ebb165da81f21c6f1e8fdd23d63c72f0cd48fc4f8074354399ec1f7705b1675e15586c1684fa1f32f985d0b4d9565258f9217cc8166cede66b9b6a337339851891b671a673c4d4d132d8eff629caf9dbddb29b66d4fe32c89dd135917192ad021e3dffa963c103592746fe0559248cae551744f47fe99e171d84a50da9917301c9c5442582833e9f5faadd771ae2f2c879290d9d23507f9e640239232b8f7cd359be06be07ddc13ff082e4220772ae42c273eddebee086259e452be105dac43e82c675cff74fc78390811770bd206b5e558166309b70042d11ab8d97632d0582fbbe76a76e8d3c2d25b079b5a21af5
#TRUST-RSA-SHA256 18aa996b0eee49e89b2dad91d327e94df24bb8a5cecdf209112b581a0ef4d2e95470eda69195131a03ca133810ac6d16e41d52d62a6fdac9ee493b7783558db2d0cbbc3230c8e7dbf525d60ae2c51332cc5adc99c5deb2e2db26c8df4948ff114bb06a47559e2375f87d9caef291014717da3256e57f3de89ec7460513fe047a8e2ede7d5c6fd7f92db24f5cefd17309424a81b4b9847083c6febf9e58767ff245bfd9c3a3985c411d447f7b0e951bb209c1981806d668415bf6fccf551758b58bff255a30450d6f50e059ac4218cbe9ff476772e11142dbdb455a9b3e916f815b9999ea9e7e7603091e8c1cd1ad7f46c086354a54ea1fd6554a77219c0d790ec3e2558dbb1bf1f59fab5748f4b8deeee84eec87f6f8d4b733b3f28336daeb4d33a4052f228f0cf43e83dad7228a4bb2cdf3d30657b12ce60c9e30c463908e879e7de22ce89d72465d5c1082e7db5fd17cbb7ac8bfa63a16808fa9fd8c59c6e121c1a700d3b406debbd56e81917930d614ff757dc90264692f0e2c203b5e03605ab4f19c1c2dfceb5ee860cf20a97ef5979da8e1e92bd0833f2bd4078693abc44e737e2c77b5e67f2e83959a6630b9f351ed0c83db8e9487a57a3dc9393932ad0e7d8358ab92736ea496358779f5180851f5bd215a59a600cbecf57e23891d6d8965e2d241ec3ab2d7c20f641b68189a4220923a6c8c25237796d196e8bdd5f4
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148957);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/18");

  script_cve_id("CVE-2021-1481");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw93066");
  script_xref(name:"CISCO-SA", value:"cisco-sa-vmanage-cql-inject-c7z9QqyB");
  script_xref(name:"IAVA", value:"2021-A-0188-S");

  script_name(english:"Cisco SD-WAN vManage Cypher Query Language Injection (cisco-sa-vmanage-cql-inject-c7z9QqyB)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN Viptela Software is affected by a vulnerability. Please see the
included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-vmanage-cql-inject-c7z9QqyB
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e6fc531a");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw93066");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvw93066");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1481");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(943);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:sd-wan_vmanage");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_firmware");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_vedge_detect.nbin");
  script_require_keys("Cisco/Viptela/Version");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Viptela');

if (tolower(product_info['model']) !~ "vmanage")
  audit(AUDIT_HOST_NOT, 'an affected model');

vuln_ranges = [
  { 'min_ver' : '0.0', 'fix_ver' : '20.5.1' }
];

 
reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'bug_id'   , 'CSCvw93066',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  vuln_ranges:vuln_ranges,
  reporting:reporting
);
