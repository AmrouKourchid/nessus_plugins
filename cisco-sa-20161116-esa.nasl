#TRUSTED 454b39d702c0d5594abce44a26fd8ae6c2e47ec2720c56a22c385c29ee247d9892c52a4d9bd796c3a454507fecd1aefd36a9561a8fc4da6b6e17a961a0c128ea07aee21ae5a972188663fbb346f70abea8457e89dfb14546351b69351f0e1521a01ad386b5e7e793afab2e587d0fee428484917f1d94999ee85becc7a9aa315c8b65681307a98e91befb5896c2cea0b824c3511e2e718a5e926f9fc0703cb1877ebfd2e9691e740658a68c2e42d4c6346accae39f1d5ebdaea5165acb5be9c64def99e26aa6692cf5a413ca7609052ba4116fb1cc8c887bfb8d08d1b52488fe2d8bf73a92c86dce19a5739820e982418f1a59a6ed9f67ac3da9e1b47ac2d90b2f4c54deef3147062d677b298d751def9bb38b798692b5780679b59f9d42e2ae04e24c372768551578fbf1ea34e0a13288f9d6dae9b13ce1fe322d4adf9295867c5a8a14eeae31b587fb57c7c55f1342a37ebce18439a83605c89f412c99c0df3825b639f863ed2731c3a3084933d401c30f2c9d93966fde23b262094b22e64e97668964a7d1fe21632eb2d01923d77ca20782ba841a215ec60748fb23dd3b8831524d9054dad4e49c40399f22f143662e113a263edee124555de7471b50eeccdc16316a882823dd0e6f6b053fc4a1e7a01237f7a19b843c0af6cd391d693128dff355d171923102f8c266f36935852fc7caf66c8d5bce4b9060c611e48f36ad2
#TRUST-RSA-SHA256 6289f71d83a45a87e5141a8bd831d320d85434125b60657775112af474dde6728dd91232839360ad375e614610fee28505fb029a3505e7243072c806d67eb67da9136f50d275570b266913d612331dbcfd300d488e81a1f51f911827e6e34343cc77f35a1694c1d76da34227cbf8622f1c90523e15632b8183d3a940a841b7bd93998e283e46871d18506efce3a2661f6b29550776f4604220483332a73750b5608e42c822c48474919b8770c07f898c9280a0f832f15089ac247eddc84bdb6afc0ab52343057e5ba3160a6d12fde97556c1bcfa7423d465626bd5408ffffe70324c978d88fbadbcc538c05557b0b79f7e7f8e892b21f4443be465cb58be76801b9d00eacc4a8e67abddf80a3654f77227c2c30e966c5b70efab944d21099e44253ce4c4d09fb371681a7e9eef601b1ce871aebbc01a5761e675246afb15e75dd029d23e73a130cf3f5f4d4ff189e46c8b203bed1273915b7e3394bef059ce9eb0989f5e422fd56b8ea33751aa0669a0d54710c76fa74585cc64e9b6f27912ce2db3db172526200e2f29984e1c140d8b85ac4e18312cb3658e8a1a49570d6ac0089a82b5876cac6b607113a4870c01672bce3c95a0f9f41f2f693f045ef682b53d81c8145e6f2ed97a5b569fdc7ccc1b633fba8de0ce397c74b9de37e08a8b1d42aa88f925d05ef80eba3e658545151d7363401d75abee1cb546aeb1c7367ae6
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(95479);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/05");

  script_cve_id("CVE-2016-6462", "CVE-2016-6463");
  script_bugtraq_id(94360, 94363);
  script_xref(name:"CISCO-BUG-ID", value:"CSCva13456");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20161116-esa1");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuz85823");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20161116-esa2");

  script_name(english:"Cisco AsyncOS for Email Security Appliances MIME Header Processing Filter Bypass (cisco-sa-20161116-esa1 / cisco-sa-20161116-esa2)");
  script_summary(english:"Checks the ESA version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote security appliance is missing a vendor-supplied security
patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco AsyncOS running on
the remote Cisco Email Security (ESA) appliance is affected by an
email filter bypass vulnerability in the email filtering functionality
due to improper error handling when processing malformed Multipurpose
Internet Mail Extension (MIME) headers that are present in an
attachment. An unauthenticated, remote attacker can exploit this
vulnerability, via email having a specially crafted MIME-encoded
attached file, to bypass the Advanced Malware Protection (AMP) filter
configuration. Note that in order to exploit this vulnerability, the
AMP feature must be configured to scan incoming email attachments.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20161116-esa1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?af6ae40f");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20161116-esa2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?84d58db7");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant update referenced in Cisco Security Advisories
cisco-sa-20161116-esa1 or cisco-sa-20161116-esa2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-6463");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/11/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/02");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:email_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:email_security_appliance_firmware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_esa_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Email Security Appliance/DisplayVersion", "Host/AsyncOS/Cisco Email Security Appliance/Version");
  script_require_ports("Host/local_checks_enabled");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

display_ver = get_kb_item_or_exit('Host/AsyncOS/Cisco Email Security Appliance/DisplayVersion');
ver = get_kb_item_or_exit('Host/AsyncOS/Cisco Email Security Appliance/Version');

if (get_kb_item("Host/local_checks_enabled")) local_checks = TRUE;
else local_checks = FALSE;

ver_fixes = make_array(
  # affected ,  # fixed
  "9.7.0.125",  "9.7.2-131",
  "9.7.1.066",  "9.7.2-131",
  "10.0.0.082", "10.0.0-203",
  "10.0.0.125", "10.0.0-203"
);

vuln = FALSE;
display_fix = NULL;
foreach affected (keys(ver_fixes))
{
  if (ver == affected)
  {
    display_fix = ver_fixes[affected];
    vuln = TRUE;
    break;
  }
}

if (isnull(display_fix))
  audit(AUDIT_INST_VER_NOT_VULN, 'Cisco ESA', display_ver);

override = FALSE;
# If local checks are enabled, confirm whether AMP is configured to
# scan incoming email attachments. If local checks not enabled, only
# report if running a paranoid scan.
if (local_checks && vuln)
{
  vuln = FALSE;

  buf = cisco_command_kb_item("Host/Cisco/Config/ampconfig", "ampconfig");
  if (check_cisco_result(buf) && preg(multiline:TRUE, pattern:"File Reputation: Enabled", string:buf))
    vuln = TRUE;
  else if (cisco_needs_enable(buf)) override = TRUE;
}
else if (!local_checks && report_paranoia < 2) vuln = FALSE;

if (vuln)
{
  if (!local_checks) override = TRUE;

  security_report_cisco(
    port     : 0,
    severity : SECURITY_WARNING,
    override : override,
    version  : display_ver,
    bug_id   : "CSCva13456/CSCuz85823",
    fix      : display_fix,
    cmds     : make_list("ampconfig")
  );
}
else audit(AUDIT_INST_VER_NOT_VULN, 'Cisco ESA', display_ver);
