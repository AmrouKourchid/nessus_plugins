#TRUSTED 55ec64cae7767d993be09c04087f070b1c6cbd111f4d5cac015b85d5ec5787725c7233c51f1c7cb414971d3ffb77be37431d16e64bfc9ea8a0de68c417142eb6d34748bb3842a4bf82e3f349817b15d494e3122c872ec161a5bc3e31ecbd24112aa68f919b536a225d2fd34de746a1ced0226b5060104bf59aa7f9e730bcaaa76e9a313991c30f88bc55b5cf736cfa25d5c9d8176de9096a7856447febc42b9072483d128619c18ced7a90bc428e83b6b9c06cd7967364b04865c879d37f8fc9e4adf1601d388ebb5f7abab7b40b9fa24e3d3d29abdc28d730a7b6049d97f34240cbe1e9e9bb2c0835fe5bc499bf69320896946333f8ed2c36cdddd56bbba85fe049f0f580353180b144a348521d2b9a7eeceefe28e8edbdb21f00d1a9b930ab21403c06bfbfecd1fafa0117a00d0c65463ce3945f3d4718766db7a84789afef338a1ea35c186c53fa7e96426949bb4e63ecbc217251ff87666341da269e0268262d266aee1aa020dd3a4576e32b74c4e5a3ba765d8d3c6d157b4334a79264670c0fd5e738f17cad040c10e801b90d5a5128ec94e5b08b2115055806ff6ad5a8afb1bea32fa737901742f757fcabb62c125abbbf3b54289702f8f335276ef365dee4facdc557696c0436d28f41f89379a08f2a8f7ad86503733edd94fa994ae158105c6dfa473740021e2e62e998221a6dab31db165e414af351e991685a14b2
#TRUST-RSA-SHA256 36927385033454d67f7f28749ac3fc88ea639cf1a45750283f598cee202b9f0da7e40429fd726aa6de59efc03034f44be583935e7117f4c41fa2fe5602737237fb26077b413898f7985ad23a66fb095e18e32ad89dadd68f0edebe1ea22f20fe3c1da360260f50f440fa3d8d3993d2d11fade2b12b7cfddda7d08e88615fe65d7a4f0ab65ead41e51dff2b1f0cfbceb2f73807ea04abc2efba05d909727418d7bce236ebf33d60e88ac2879af4f86b23a221c8c30f563fda5fb52da673d6d26b021a940558e0a9880512b065501a31c2da0d194d7f9a73b6e33a3994ee02aeb0f7b7912d1aafcf4f0219bdaf2175f85ca22af820cf99087eead416d83378e6792fbe4233b8ac53fde226d68aa4e8a379309aaab6e4fe50a97b3f24014222de693b17c3b5140044468514ce14ceb823e3644d733f6c1fc560504795d167458f8f25b1d3e4867b7cebb0505c2756a06ceeb591df89c6133215a79be7914644b9ece187165f922f292f83e8bd7bd45b792ae7255cd28ce03c0bb2e0600494f2bf5cc15c324e362f926ac44d298da20ee83657e7be0801ccb1a0237794ff015a2a11879b47910a2f074498870fc1d58da948f4727d56db4f8a84b800f701b7d0c2d341798e971c44b643bacaa6c48e456622a47878b8a941d3d6d5b3d49ff6700290da327e4622f80f6472e4b4f93f8c88703f337c56c8ca4dbfb6a66955b3cb99fd
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69471);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/24");

  script_cve_id("CVE-2013-0137");
  script_bugtraq_id(60810);
  script_xref(name:"CERT", value:"662676");

  script_name(english:"Multiple Vendors EAS Authentication Bypass");
  script_summary(english:"Checks the authorized_keys2.dasdec file for the presence of the compromised key");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an authentication bypass 
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote EAS device permits root login using an SSH key with a 
publicly available private key. The private key was included in 
older copies of Monroe Electronics and Digital Alert Systems firmware.
A remote attacker with access to the private key can bypass 
authentication of the root user.");
  script_set_attribute(attribute:"solution", value:"Update to firmware version 2.0-2 or higher.");
  script_set_attribute(attribute:"see_also", value:"https://www.kb.cert.org/vuls/id/662676/");
  # https://web.archive.org/web/20130712221439/http://www.informationweek.com/security/vulnerabilities/zombie-apocalypse-broadcast-hoax-explain/240157934
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?637f824e");
  # https://arstechnica.com/information-technology/2013/07/we-interrupt-this-program-to-warn-the-emergency-alert-system-is-hackable/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fbb8fb12");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-0137");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/06/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:monroe_electronics:r189_one-net_eas");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:digital_alert_systems:dasdec_eas");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013-2024 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_ports("Services/ssh", 22);
  script_require_keys("Host/local_checks_enabled");

  exit(0);
}

include("global_settings.inc");
include("audit.inc");
include("misc_func.inc");
include("ssh_lib.inc");


enable_ssh_wrappers();

if (!get_kb_item("Host/local_checks_enabled"))
  audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

keygen_command = "test -f /root/.ssh/authorized_keys2.dasdec && ssh-keygen -l -f /root/.ssh/authorized_keys2.dasdec";
line_count_command = 'test -f /root/.ssh/authorized_keys2.dasdec && wc -l /root/.ssh/authorized_keys2.dasdec';
keygen_expected = "1024 0c:89:49:f7:62:d2:98:f0:27:75:ad:e9:72:2c:68:c3 ";

if ("Linux" >!< get_kb_item_or_exit("Host/uname"))
  audit(AUDIT_OS_NOT, "Linux");

ret = ssh_open_connection();
if (!ret)
  audit(AUDIT_SVC_FAIL, "SSH", sshlib::kb_ssh_transport());

keygen_output = ssh_cmd(cmd:keygen_command, nosh:TRUE, nosudo:FALSE);

if (keygen_expected >< keygen_output)
{
  ssh_close_connection();
  
  vuln_report = NULL;
  if (report_verbosity > 0)
  {
    vuln_report = '\nFound the RSA public key with fingerprint "0c:89:49:f7:62:d2:98:f0:27:75:ad:e9:72:2c:68:c3" in the authorized keys file.\n';
  }

  security_hole(port:sshlib::kb_ssh_transport(), extra:vuln_report);
  exit(0);
}

if (report_paranoia > 1)
{
  line_count_output = ssh_cmd(cmd:line_count_command, nosh:TRUE, nosudo:FALSE);
  ssh_close_connection();

  matches = eregmatch(pattern:"^([0-9]+) ", string:line_count_output);
  if (isnull(matches) || isnull(matches[1]))
    # This is set to 1 arbitrarily. It could just as well be set to 0.
    # It is set to something <=1 to pass the (... && line_count > 1) check below.
    # If we can't get a number out of the wc -l output, we can't advise the user to manually audit.
    line_count = 1;
  else
    line_count = int(matches[1]);

  if (line_count > 1)
  {
    audit_msg =
      " Note that Nessus checked only the first key in the authorized_keys2.dasdec file,
      yet the file has more than one line. Please manually audit this file.";
    exit(0, audit_msg);
  }
  else
    audit(AUDIT_HOST_NOT, "an affected EAS device");
}
else
{
  ssh_close_connection();
  audit(AUDIT_HOST_NOT, "an affected EAS device");
}
