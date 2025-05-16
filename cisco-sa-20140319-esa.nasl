#TRUSTED 1b267f3cec6f0bd531b3124dae250946df8dbc7c18165b991afee38a46fb6e79d5d90af312fea5194575630377b63f681e85cab94fa0ac472e6dcbbc8f7f97f36e14ce8ce2bcfa04482ca776a4d40d98ed2da336aec1ec41bca3fc5a8339a49488efef9b09d1f092b544acc76d333c8702f7ea76c16a9c5af74456a62729459ab7ecbe5c026c69845bb52d0d62a52156f3b2d1a0ac5a40e4c1b60cfbdfa7e08276c150491aa231ccf59751b509f560583dc28f8526b99ab56ce9416bbe7fece87f40361e709f91ba95dce2015ae3a6614a6431ec8e0605e99b3494176a875b2ed430a9f3022e0af08a28bebf9d935017779b50328c1ac7d6aa8d4759aede7f5020c34ef7c624a6c09237aea25afeb2aad0690387d90e6f20c84d2d46f9eee32d088e9fd13ad2a8b1aec0b50076f6cc56de268be691e7088863e31f547422fc18b9672d3dd461563caaa4f248c2e1c65d6d66c9681f21e0a51d249e8347bdad2fcf49158536265c12ceec5ca328b57a23dc972b36c8ffb1b6a08c26f7b874767b398072ff4f14b745c2561261192f1f7760b02b201e918cb22726e2d7ff36d757c932f52a7d5409efd2237c61922ad5b62aa61ddae44ff5a5d69cf9207856104618326ab40cea7b9fbb5ed31174c1bb2df6e8be730a6eb7084f41978b5ede97acc14ce3418092d9e8cdd4ad7ebcf3a4148884a1a4e9309c56a1289b728f93b9e7
#TRUST-RSA-SHA256 8446a16d475136a70d29ad764c9df44ef82cc59cf19d350598ecd185e975b985275e38c2eddaedf0075c02e87366f3a10dd0609dc9996f2e3c2b5c8ff3c7dde0f45d70c94e0515ef6d86d9bda4598f9934c65870eeb131407d933920be6b6bc164bf908c4403aa32f32737838d4faf3c86c3d9a1710adbae721bc9f777c2445907032618ecfd1b8b2d573f933abbfd8efbd9befc577edfa8d7af712a8fc3c6fb1e3e3e764deb7e3a97198ef530e0594e42b60eeb808d00e907e7f08f339468bde5380fdefeea75cca5bc2d4f60f17c4736fab8e91c8b9f0cf584a62dfd5cd5503b930c877cff7be7e2c3461b5ce8f063e35bef95fef2e09d08ee0d497574ecf60983ad85b44c64291074595dce53d0309cc7911866db520d99309dd00f887535936ae19541010847fcc9cc2abadbc0185206317af19944453f8adaf2d21bccc38c7fd61517acc602997d47580b9d80b3076b9d74d9b6fbca53c08bf4e2c94086878a6b3a65f566f3523bf27364cfdb58410ea9a9349fb1eca82e2914ef4f05220c271fc987e0315c7ca87cb3de19b395e296d4b342e2da14efc76caf6038a4355a73953f4c05136949ef195bae7be55eaf2030f0a966df68f34744243e6dde5280293c2fe179117418efdd09b895d442db81ee7ac44ef51cb47cab022978c9ac595fec840fd2d75f5bf4596009dbf0715b1724f1118fc7198b699f7251d0ee5f
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73210);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/05");

  script_cve_id("CVE-2014-2119");
  script_bugtraq_id(66309);
  script_xref(name:"CISCO-BUG-ID", value:"CSCug79377");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20140319-asyncos");

  script_name(english:"Cisco AsyncOS for Email Security Appliances Software Remote Code Execution (CSCug79377)");
  script_summary(english:"Checks ESA version");

  script_set_attribute(attribute:"synopsis", value:
"The remote security appliance is missing a vendor-supplied security
patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version and configuration, the Cisco
AsyncOS running on the remote Cisco Email Security (ESA) appliance is
affected by a remote code execution vulnerability in the
Safelist/Blocklist (SLBL) function due to improper handling of SLBL
database files. An authenticated, remote attacker can exploit this
vulnerability to execute arbitrary code with the privileges of the
'root' user.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140319-asyncos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c66d063e");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant update referenced in Cisco Security Advisory
cisco-sa-20140319-asyncos.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:email_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:email_security_appliance_firmware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2014-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_esa_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Email Security Appliance/DisplayVersion", "Host/AsyncOS/Cisco Email Security Appliance/Version");
  script_require_ports("Services/ftp");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

display_ver = get_kb_item_or_exit('Host/AsyncOS/Cisco Email Security Appliance/DisplayVersion');
ver = get_kb_item_or_exit('Host/AsyncOS/Cisco Email Security Appliance/Version');

vuln = FALSE;

if (get_kb_item("Host/local_checks_enabled")) local_checks = TRUE;
else local_checks = FALSE;

if (ver =~ "^[0-6]\." || ver =~ "^7\.[01]\.") # 7.1 and prior
  display_fix = '7.6.3-023';
else if (ver =~ "^7\.3\.")
  display_fix = '8.0.1-023';
else if (ver =~ "^7\.5\.")
  display_fix = '7.6.3-023';
else if (ver =~ "^7\.6\.")
  display_fix = '7.6.3-023';
else if (ver =~ "^7\.8\.")
  display_fix = '8.0.1-023';
else if (ver =~ "^8\.0\.")
  display_fix = '8.0.1-023';
else
  audit(AUDIT_INST_VER_NOT_VULN, 'Cisco ESA', display_ver);

fix = str_replace(string:display_fix, find:'-', replace:'.');

# Compare version to determine if affected. FTP must also be enabled
# or paranoia setting must be above 1.
if (
  ver_compare(ver:ver, fix:fix, strict:FALSE) == -1 &&
  (get_kb_list("Services/ftp") || report_paranoia > 1)
) vuln = TRUE;

# If local checks are enabled, confirm whether SLBL service is
# enabled. If they are not, only report if running a paranoid scan.
if (local_checks && vuln)
{
  vuln = FALSE;

  buf = cisco_command_kb_item("Host/Cisco/Config/slblconfig", "slblconfig");
  if (check_cisco_result(buf) && preg(multiline:TRUE, pattern:"Blocklist: Enabled", string:buf))
    vuln = TRUE;
}
else if (!local_checks && report_paranoia < 2) vuln = FALSE;

if (vuln)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + display_ver +
      '\n  Fixed version     : ' + display_fix +
      '\n';

    if (!local_checks) report +=
      '\n' + 'Nessus was unable to determine whether the End-User Safelist /' +
      '\n' + 'Blocklist service is running because local checks are not' +
      '\n' + 'enabled.' +
      '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, 'Cisco ESA', display_ver);


