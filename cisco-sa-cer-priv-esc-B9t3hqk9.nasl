#TRUSTED 0d856a581c9b537de786eaa19b319a3e4eea500ff0ed1a71f1d8e25682abaf615f0fadcc1887668d876c4f8b50e1a5c4657973e4892b91aa29bf32db108049be8aaeaeacde8c62ff4501048b2808f47991cf4d57ff3a2cc1185a67650c1ac27d0b1474105e6640dd5fb0dcdc7dd67c833047ccf0c024b1b40be2d1045ed368342b364b357519ac360bb19b4247eae0eabd4ae1e9578da842de26a0ee2e23977a8b5231eda328d09ba7ea49e7a70df281030b3fe15d78a917ca164114e352a8a4cabda9f37492b3ac937511bacffcec25399cef3091d2643e4e87cb8f6e40b6cdcdd0ee728bf9851b9c2486c069e5149ad040c2b08c6c7e17da6207ca58aa9a0a0074ff46595dc986844b270acf1e6b91c4eaa89cf90b4a6fa7be687d738fc4598373cc56a2695655126f886a95e6d4d04d33681f4d346430739492e2df242d40685e7fc54feb094fc049062355ee5476b372781e8adf4a1de27277f37fbb26ed7e5674e04783437a07e2eb3ea5fe7dbdff6a9f123fb94f66096ca672a82cabfce9f707e78e02b28461373dd0377eb625ad828a501d625299cc15bf4a6a7325b2bd1b992e20c73ad2d4e58fe5e68e7ceb44743d33bf1b07a2556451c4d8112e1ea484f8719803157b9101f38218e8957dce92984a757d4222f5af9f46b01973c81b858043d3cb896b42d039eb8f3a2ce25ac7988534c4554dedff7a795b4b725d
#TRUST-RSA-SHA256 899e335fbedb080cbec14ccc6ae504d70d45899128e3866d20518505641cd7640fbb48880eb91326a2963f52a06723087e8f6fcf195b47c2175215db5e6acae5c8845966aa11da45f4eba2c382843c50c86a7566c1f13055906fe98e231b3ebd328acf526d646219c1319a84cbc2a6d84dd3cf580c1d03ddedd1d83b1f216374238d274c1140c5ad7f6075f24e579102056c295e39680486d5b411cc3a16dd9be38dc14b3434f596812026f478b56fe9ccb47dd9a16b9f84295e9fbceead7fde1df149764506af1be6210abbc29aea9515c8b98dffc3ea5c08b8e0e2e4d51da5d215504bb389bdbc920f4130ea0196502d04ebf3a923c5cd8c244b24cda733f78af340c0bb480c995714b18e35cd2cd415b14caf6976cd8ad14a1d8fdb1464e22988abe8ea64703a5ba95c80614468bfd76551b117a5d4dfc25b5cb9bec5137e95acba6ef9ed1fa273a0c589c5b130877b7155361585bad6adbed04eb70f73e9f846f06a8111cf3de3753c1b2b375139b802d242aa2c01f908671a5e24f5126dd84a53ad970984bb3722d04f721b97f516b3291818db10db7f981b88ccd33aec12bc42071ec78bedc242cf414a17030fbc21cf1f962938edd15b4f5d0355c175e304ee21caecb62c05e66b9d72811d27c48a2430faae583467344fd845fd3769c3723cfc3fbf72498f41bee7840bfd76ae518c37616aa5e87115f8a8785c41ce
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(183037);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/10/13");

  script_cve_id("CVE-2023-20101");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwh34565");
  script_xref(name:"CISCO-SA", value:"cisco-sa-cer-priv-esc-B9t3hqk9");

  script_name(english:"Cisco Emergency Responder Static Credentials (cisco-sa-cer-priv-esc-B9t3hqk9)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Emergency Responder Static Credentials is affected by a vulnerability.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cer-priv-esc-B9t3hqk9
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?10184428");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwh34565");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwh34565");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20101");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:emergency_responder");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_voss_emergency_responder_installed.nbin");
  script_require_keys("installed_sw/Cisco Emergency Responder (CER)");

  exit(0);
}

include('vcf_extras.inc');

var app_info = vcf::get_app_info(app:'Cisco Emergency Responder (CER)');

var constraints = [
  # https://software.cisco.com/download/home/286322260/type/282074227/release/12.5(1)SU4
  { 'equal':'12.5.1.23900.19', 'required_cop':'CSCwh34565_PRIVILEGED_ACCESS_DISABLE.k4.cop', 'fixed_display': '12.5(1)SU5 or patch ciscocm.CSCwh34565_PRIVILEGED_ACCESS_DISABLE.k4.cop, Bug ID: CSCwh34565' },
]; 

vcf::cisco_cer::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
