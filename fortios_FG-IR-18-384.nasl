#TRUSTED 6b900b11ed568c6b87ed8a24404121b6ed5d4f8f14e9a6bddb6c6aa1356a2c3493200c927a3c12abe4462519bc199420d69d5b0616b50d6edb1eb30bd98988cb05e5b02eb787fd101aee20b957710d2380d2b282863c90e53ac2a0965b8b1b962da33c1239c98fd35bd6b30b562bbfd0893197b4cb08ad241f75a7196e7d59da0c4031e3061909967d3fbcdfbbe526b8e9c869f72c31095bb3be452e9a6aa4bba58409ec95320c4f28ba3f7f2777875db01d66622e33588bb412669abd6c3de327f7f1c712f539e55e38a489cb788643241e7afc2a7a15383434dccccc164aa24e366eaf55e26d226e8e0263c6e7561af1420dd74402715e435458ae42e6205a516f771a21cc7f8779080d9b337922818081f40d2d43a7cdce33ec90c6ebe78ee10e39cf7c70463db09b711e639ea5e7be609ad93ed61626d3ce65920c54f73bea47132a380e65d92df787751a2acddfba079acc5b74ab08166a27e2baabf3d988ad3580e086c311ec1d7a7d334ad5742c35bcdd2a8af279bd1fd98587c658b084f5585371f1cafeda60c54796975f5d396d8f8385677b5a430cdba57463c271d67bcc656629a129a1c365420301f2cb09c8544a64d052d46b797f033917231d41281f751bb63a6210963d466ff750e90775ef2512ae67cf0974d0cd4f20b3aad3a8acd720ccf48c69ca29aa3f2efdb6045f5b56efce0f5c582a9f8129931e76
#TRUST-RSA-SHA256 952c7da45278823fa96026dd489bff1bd0f601073d38cda3ef552fcc80cec42fffe0238d7f50bacb66d049bbefa126c51570feb1ad2fbda07a5bbb5148ad19f34d586f5630fec3d28c47b762babd020cbece08d41288c0ab84db41deebe2d883dcce1e330e14b1dd6297ce398a017824871cb45171eddf29c99ec611f580eed92e60f6f7fa214e5ed2d8b9af153f3a742fff5e15876ab5db1a2c82c6bfacb4ce539408c08d32acb32825e9fc7b260c6cb0a508de4fd960b65a84706c79401e624a386461028d535b68bceaa1152d433150c3bfa35659989ef99794bb01c0f5755c83cb2717b651ff72f738d753aa372cdefddfbe109fd55280a7d615f8e6f445939c60f383d7644c77a2b1b9357d4699da73ef50ff9a0d9c6c9603a8d86915d272640e9da76e8e8979b2122c698f091f1a8e65c2055f43030cc6af12a3da2b2a5602989ff8d8480cdd08cb1f56a444d73f8e586b3854ef1b8e8bf03231ab505c75718f2b707c25d8534a144332c39e1494a4973322c5b44f29a37b936125604580efcf2faa89a894f6cd8adc0504ccd30d673bd26364c615b5267223a4cd5bfe2e83bbaf65f9278b7acae6a59dada68922da03b8fef15faf8a775191a961537bbb311c0e447b0d848c507835340b0d72793903f964ca3e46d6489cbd8794ac0c3876afe8b1bf0f1905ba98b39ab8d9156f5c2281e551bc35720e0f22e435e6d2
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(125885);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/07");

  script_cve_id("CVE-2018-13379");
  script_bugtraq_id(108693);
  script_xref(name:"IAVA", value:"0001-A-0002-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");
  script_xref(name:"CISA-NCAS", value:"AA22-011A");
  script_xref(name:"CEA-ID", value:"CEA-2020-0129");
  script_xref(name:"CEA-ID", value:"CEA-2021-0020");

  script_name(english:"Fortinet FortiOS 5.4.6 <= 5.4.12 / 5.6.3 < 5.6.8 / 6.0.x < 6.0.5 SSL VPN Directory Traversal (FG-IR-18-384)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a directory traversal vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of FortiOS 5.4.6 prior or equal to 5.4.12, 5.6.3 prior to 5.6.8 or 6.0.x prior to
6.0.5. It is, therefore, affected by a directory traversal vulnerability in the SSL VPN web portal, due to an improper
limitation of a pathname to a restricted Directory. An unauthenticated, remote attacker can exploit this, via a
specially crafted HTTP request, to download arbitrary FortiOS system files.");
  script_set_attribute(attribute:"see_also", value:"https://www.fortiguard.com/psirt/FG-IR-18-384");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Fortinet FortiOS version to 5.6.8, 6.0.5, 6.2.0 or later. Alternatively, apply one of the workarounds
outlined in the linked advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-13379");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Fortinet FortiGate SSL VPN File Disclosure");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fortinet:fortios");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2019-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("fortinet_version.nbin");
  script_require_keys("Host/Fortigate/version");

  exit(0);
}

include('vcf_extras_fortios.inc');

var app_info = vcf::get_app_info(app:'FortiOS', kb_ver:'Host/Fortigate/version');

vcf::fortios::verify_product_and_model(product_name:'FortiGate');

var constraints = [
  { 'min_version' : '5.4.6', 'max_version' : '5.4.12', 'fixed_display' : '5.6.8, 6.0.5, 6.2.0 or later' },
  { 'min_version' : '5.6.3', 'fixed_version' : '5.6.8' },
  { 'min_version' : '6.0.0', 'fixed_version' : '6.0.5' }
];

# diagnose sys top <Delay_in_seconds> <Maximum_lines_to_display> <Iterations_to_run>
# We want to make sure we see all processes and only display it once
# If sslvpnd is not running, host is not currently vulnerable
var workarounds = [{config_command:'diagnose sys top 1 200 1', config_value:'sslvpnd', misc_cmd:TRUE}];

vcf::fortios::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  workarounds:workarounds,
  show_check:'Run Time:',
  not_equal:TRUE,
  severity:SECURITY_WARNING
);
