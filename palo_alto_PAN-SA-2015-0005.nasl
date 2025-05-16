#TRUSTED 71233aa3cfce80afde6f2d0ca2662e7c51f40cff7626e2f60b5a6839c81d46ae58ffbcf451509f9ea33bbb89e8b9b188f9818f62070024584f42e0021ccaa96aa4f47742d318c05ecd18090cc96483a378c74d6030a1ce761f39e3d948c3ec742a0e28bd279ba9efbf2651eed80e3ad93a01a2dcbb684fcf8359727913ae4d72665a347be1f83b6af151b2984de9f71474a0334de1523d9702e4352acfbb4d25a417c67941731f59929999d47bdeb4519ecdc27447a88926174d91962cd29cd224533d66b075a461cbb1658d8d0e13a6b51003b715e0be2cf2ad1c75da84cad1db089a36d181d2a65193e0cf801e77eb21290b5f7125ce706dac7564efbe90f5161a93d78127b804048c5b70e53cbd21447e5a3cfaf8d65033b4889827eee7444942a721648ed73ea61c0bafe75dd9653100c99aa3800e5855921f3beb7cf18ee65c47a2973e213e13ae9decd1a5f35e55533ed94f125d6a0cf471831d6a4e18ccf2c211a160aee5487fd4cceb7185f045f9f2c901082c21621cfafdebed4ff4ed66986a36a22da7cb0e295bfea98ac891bb918e49f6d0c33404881e9ed289039c4816698f35c60d37d88ae6f609c2bb53c9fdfebb5eec033be338be8533e64ba66fd4cda275d9a3f193ab46cedfd97f9d5cfcdebd529b50b72938d90e6015b3ca2c42d6819d57c248f71efe97e18395a1203fba8792a51489771f0de9f6c058
#TRUST-RSA-SHA256 a61d60c649dddad9131c9a66fd505298fbfeaca5718b15fd01aa5ca08f78f433f8e95f35d3bf63118c0206b6b5d2bb291c9afc93d9d1aae2495c6ba04cc5ce5f82bbc37a1d6ea5eccf88cd41f6ab260862984e790981e46fa3a14c7a72d6b81138205dd8f055e7cda99988a1c189c1d97f8d26c439b9b7f412a683c911369e373eeacbda305b28dfa75f5985f171956a758b1faec0b6f3faf8c4e03b1416c6dc96c7d43c21b8706671356e3f75de57272f94a1e96d30d73d16ca5f7e7f440a62e9d91d1b795f379762d8219a20f3e8da9572fe5b29e44ce2992ad31cdabd721c5c225ba6a87efb17541428809110a80fed7f49b583e86236cdd79f063c17e521aef15e42964dea4f718e169a21e7db0d12035618b4f48760f9cd0563d5dd060559fcc00909b159e51ddf9ac976dd85a07ee51176c617ff30da36dc844b0b276fc8c4c63728ebbb79490c67764634ce986f71892f22707702edbaf2da0f3556a227e21ca308b304072ccb5ec993a930453fc83fd76f5336e03b71ddbf5f827c060b41f797459cecc81d229025d0e67f4612a92fb925bb3afe721022c78c2c2274c78399e986f445bc9ee801e1807c7441ebc9367dcc16f8cbfac9d5f3f4a8b73c515429e224620ea43f72ba9bfd067633b4da273f219c4112f8edf2b682d89f48ccfef0592ce7964d0b7ffb73b32b291224436f8aac199516bcf318d9c21d6282
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85535);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");


  script_name(english:"Palo Alto Networks PAN-OS 7.0.0 LDAP Authentication Bypass (PAN-SA-2015-0005)");
  script_summary(english:"Checks the PAN-OS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an authentication security bypass
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Palo Alto Networks PAN-OS version 7.0.0. It
is, therefore, affected by an unspecified flaw in the LDAP
authentication process. A remote attacker can exploit this to bypass
authentication checks presented by the captive portal component or the
device management interfaces.");
  script_set_attribute(attribute:"see_also", value:"https://securityadvisories.paloaltonetworks.com/Home/Detail/32");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Palo Alto Networks PAN-OS 7.0.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/19");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:paloaltonetworks:pan-os");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Palo Alto Local Security Checks");

  script_dependencies("palo_alto_version.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/Palo_Alto/Firewall/Version", "Host/Palo_Alto/Firewall/Full_Version");

  script_copyright(english:"This script is Copyright (C) 2015-2023 Tenable Network Security, Inc.");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");


enable_ssh_wrappers();

if (!get_kb_item("Host/local_checks_enabled"))
  audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

app_name = "Palo Alto Networks PAN-OS";
version = get_kb_item_or_exit("Host/Palo_Alto/Firewall/Version");
full_version = get_kb_item_or_exit("Host/Palo_Alto/Firewall/Full_Version");
has_ldap = FALSE;
fix = FALSE;

# Advisory is very specific : only 7.0.0 is affected
if(version == "7.0.0")
  fix = "7.0.1";
else
  audit(AUDIT_INST_VER_NOT_VULN, app_name, full_version);

# If we're paranoid, check for an LDAP profile on the device
if(report_paranoia < 2)
{
  cmd = "show config running xpath shared/authentication-profile | match 'ldap'";
  buf = ssh_open_connection();
  if(!buf)
    audit(AUDIT_FN_FAIL, "ssh_open_connection");
  buf = ssh_cmd(cmd:cmd, nosh:TRUE, nosudo:TRUE, noexec:TRUE, no53:TRUE);
  if("ldap" >< buf)
    has_ldap = TRUE;
  ssh_close_connection();
}
else # Otherwise assume the risk of FP
  has_ldap = TRUE;

if(fix && has_ldap)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + full_version +
      '\n  Fixed versions    : ' + fix +
      '\n';
    security_hole(extra:report, port:0);
  }
  else security_hole(0);
}
else
  audit(AUDIT_INST_VER_NOT_VULN, app_name, full_version);
