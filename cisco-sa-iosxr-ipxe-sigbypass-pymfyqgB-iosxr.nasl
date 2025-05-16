#TRUSTED 639df8ae98a6872d77aee78c660f82c3da5447f3a8fb6e67a76535f8408026663d28ee963bc012c8f750223ebc8977961e633ab2e214739c2cd5c1588354fdd78bca176ce1f6544335b557c7d9ef346bbf4b89baa40b2992a593e1dcf8037f2e1351f4e897d20ce97f35740d188d63583a2311f09af15bfd99bf2e76b32af6e45029f1e9070006385c35dc539b63ba8ec2123cc432a4ef025d132b394649b6059f8344b0ced8cf56994616a05bb1da66a1e4a52e46a1a9073d921d55be1ef35d7bfae6c6cc8e4344122e9151d30ce418b6339f20bf6cbfe2fc57c032ad312ec2895995722681ba071faa43a092e203134254beb0858cc3837edaa1ad6fe59ac74e9e03b19163d887a12bf01f661792073e511fd362dfcfe4638d9daa2848b9365119b0afd3fb5f23e5e0d75833a1388b1957fe65a231a67b4b3054edd3511ee3b239ded5730bf3a227b81e93f938ea2b66b54adb3f57c58642e25b9fae5676fc0e007c7219de1875c7526abeff5e1623961d284e62016b356ddbfd3e072723c53055585a911039be69fe1a0563f81e58ad84d575a11dd101b3190d97d71f666ad557edd24e9d400bb26391aef9b107428b73bdd6db35c68ed5c43f4be6f112dd4164b0231dd94e2f455c66bf3df7882428890eb16a510a5ac918debe7d964aa171d35e49302074dac21e3ca8742dded478fbbc335622817a319a7e547e3181d6
#TRUST-RSA-SHA256 45d9d8b0111009d07cac0ab56361805e010e4ca01dc5f9e7e4644b82c7b17f3a7aeba1edae17d63754824c78a6188ca91d3175fba26fac5fc7e847ccd02680f33e8a481fcb011cc59c8917f58b44c7b6772e5d15800035e778623bfca585f0c58f20c1cefe707c47de8a91371e05c94f5453b9e72253f60097e0e6ad40a00e5705a3994015f8490cab07a56899b32b99f42172a30b0a825563867b4a7d88461e2ecdf7a7b70bfc257cafd28451935218cd039c64dc4cdcf2476b6743799a150e237fe3913e0a67e4c09e4c7ee30c37e2a6d2e5b185655cfc9a0dd56c32c1789038bb5930d70cd15d654e01427dd8f2b6148fd1b46fcbe16b22b9d1631615149258ef2af7a311c390966166b6bcc0cf5e22abcd47155308121532efe7435721d52018095a093f371c72b1c040b98d7b0850c7752df495e4bf8e136bdeff0f056dedc8bbc9882c8cb7f512ff4e84f371127dc5e022da7e4f50ed7f2bd5f4fd5b4ae548191a63a611941222cc0c84d1da548778c9a420bef2ba6bfa6cc793544022c34d178b70a91f87e8cb219e69bbb9dd79066827e197b5c3342500c53359e358c955fb81120abab4b3e62bd98054c258dacba0cc0c785171160be7fd76d0456177200a649dca6f684dd14d106812b516345b130fd816b30f6219709935fe4ecfd8914cea17bede7c6d4f1ad73c1256822c41100615343efddcb5fb914363313b
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(183213);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/13");

  script_cve_id("CVE-2023-20236");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvz63918");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvz63925");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvz63929");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe12502");
  script_xref(name:"CISCO-SA", value:"cisco-sa-iosxr-ipxe-sigbypass-pymfyqgB");
  script_xref(name:"IAVA", value:"2024-A-0169-S");

  script_name(english:"Cisco IOS XR Software iPXE Boot Signature Bypass (cisco-sa-iosxr-ipxe-sigbypass-pymfyqgB)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XR is affected by a vulnerability.

  - A vulnerability in the iPXE boot function of Cisco IOS XR software could allow an authenticated, local
    attacker to install an unverified software image on an affected device. This vulnerability is due to
    insufficient image verification. An attacker could exploit this vulnerability by manipulating the boot
    parameters for image verification during the iPXE boot process on an affected device. A successful exploit
    could allow the attacker to boot an unverified software image on the affected device. (CVE-2023-20236)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxr-ipxe-sigbypass-pymfyqgB
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e01dceae");
  # https://sec.cloudapps.cisco.com/security/center/viewErp.x?alertId=ERP-75241
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6a0abd7f");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvz63918");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvz63925");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvz63929");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwe12502");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvz63918, CSCvz63925, CSCvz63929, CSCwe12502");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20236");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/09/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/09/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/17");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version", "Host/Cisco/IOS-XR/Model");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XR');

var model = toupper(product_info.model);

# Vulnerable model list
if ((model =~ "ASR9\s?[0-9]{3}") || 
    (model =~ "NCS\s?[145][0-9]{3}") ||
    (model =~ "NCS\s?5[46][0-9]{1}") ||
    (model =~ "8[0-9]{3}"))
      var vuln_ranges = [{'min_ver': '0.0', 'fix_ver': '7.10.1'}];
else
    audit(AUDIT_HOST_NOT, 'affected');

var reporting = make_array(
  'port'          , product_info['port'],
  'severity'      , SECURITY_WARNING,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCvz63918, CSCvz63925, CSCvz63929, CSCwe12502',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
