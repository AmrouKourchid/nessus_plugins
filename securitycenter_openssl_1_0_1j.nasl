#TRUSTED 3f8e3167c719accd1040d3a7fcf76aa1984c5fb18a2434259c6e7560edf5acbdd0d927817ad80923ab185cf77ddb518d521139a8e976c6d977b0b302fa2f4e7f93c5da5547bb86de8943e036edade002217458ba55bacfb836122bfa0a73f900a6e3239acd87199656b339f3ebaa21f99871c3cc7690e73dd4a975a73b17a7a3edf0ea73b63468a8fbadb80cc16821605fdc71b01e737f32e0aa017b00bd05740d7744c0d7812376bc8ebc7141776218a406a7643366d9353a487517ab7df5ddf95752da9c2dea393d10affd8e032514042595bf9434bfb7057f2dc5133b615bcd96ff977a8edead85561e62920654707ffdf6221794ae5529d28e43fcd2d80678deaaa907152efed699c63112c5333e23f32e09fca6798287fad4b40c7315585c6e34ce3e7d3fe33ff2903f283cf68ba0cae820ad707db89bb67249a1fad8fed9f4c5686cffb25294d3152acdf7d5f5556268204a36ed737067ab32d452e329e7eeb20b686d7969dce371bcd3e711cc3f4cac1c5fd3974a207df7d5b4e8438f1ba345aea5280140becfcaaeed88c6b65f67b655b8502f05b2b3cd5678809c200e6de8cca2b753c8406bba43a5e3a98842ed26e0144e7e7ced8752c5e9624c2f95e45943bca25c6982978d57e237950df62d213efd7aabad2ffbbfc70390ddb2595b9b684a27867b54fbbfae2a24747bd46d5dd7fdd88568afc5f3a15eeb4fb7
#TRUST-RSA-SHA256 62e93db9329f4ef9c4840d0c53f02bf4d1418b47af94e7d2d4a3e45fbe06374abe2e793611fc158bfbc6c6363ea9a55e88183f524455f39a4fda2e66dc49512e05307c78a9abfad3ec8a199f6730aaca467c9c70b467d1ba9f679143a6dcc2ad022ebb46c0513683c39a25eb4d1fc6e89ae0e87445ed0241244d7cc63b0e0d10eece58b8297eedfa897c07dd67aa350f49c671f2de6f88bc794290ab897fd6ef8cb9965036167b8306d48fd954bc010a8c8f4e87f4d70f157a9da96940b465792a7df98d6033e4623031b91c6a955920d4523b94cd0b4013fd5262e96d72d4bec57243a89586172d21d5b7906e26f2b671eb783a5437143b5595d2dcef020ed0989969f04482240b54cc8d1df62eb07364b38e861f552738a6ae6059a7e72748fa4d06309e087846c55d5f2ee67f9e9ca1337ee553ecfaf272ad6d74bd798534c3824ee868580a12b3e9dcc98dbbb1689bb502bebcc78271fcb2b9dac550d5e63a7505c14e3e5cc41e2c1a6cc944750e8da123750d0b7605cf85a0e6d564df58f1b3abc8982cf69fc7e137af8149fd23ba7318ece77f414ee7baf5642fa85903e77fd61ab85eeda8557ffb4c38b9477619f54ec6c3632d53a8e8fd9fab22ad305461c65f62fce11ffffc959f70d3398abc4fb3190026680fd0903ffd1c01a337af247ccaccb90e47d6c98558d011955f36b89c0b30ac2c28b55f5410288c5659
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80303);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_cve_id("CVE-2014-3513", "CVE-2014-3567");
  script_bugtraq_id(70584, 70586);

  script_name(english:"Tenable SecurityCenter Multiple DoS (TNS-2014-11)");
  script_summary(english:"Checks the version of OpenSSL in SecurityCenter.");

  script_set_attribute(attribute:"synopsis", value:
"The remote application is affected by multiple denial of service
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The SecurityCenter application installed on the remote host is
affected by multiple denial of service vulnerabilities in the bundled
OpenSSL library. The library is version 1.0.1 prior to 1.0.1j. It is,
therefore, affected by the following vulnerabilities :

  - A memory leak exists in the DTLS SRTP extension parsing
    code. A remote attacker can exploit this issue, using a
    specially crafted handshake message, to cause excessive
    memory consumption, resulting in a denial of service
    condition. (CVE-2014-3513)

  - A memory leak exists in the SSL, TLS, and DTLS servers
    related to session ticket handling. A remote attacker
    can exploit this, using a large number of invalid
    session tickets, to cause a denial of service condition.
    (CVE-2014-3567)");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/tns-2014-11");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/openssl-1.0.1-notes.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20141015.txt");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/vulnerabilities.html");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in the vendor advisory.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on analysis of the vendor advisory.");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/30");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:securitycenter");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("securitycenter_installed.nbin", "securitycenter_detect.nbin");
  script_require_ports("Host/SecurityCenter/Version", "installed_sw/SecurityCenter");

  exit(0);
}

include("openssl_version.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");
include("install_func.inc");


enable_ssh_wrappers();

get_kb_item_or_exit("Host/local_checks_enabled");
sc_ver = get_kb_item("Host/SecurityCenter/Version");
port = 0;
if(empty_or_null(sc_ver))
{
  port = 443;
  install = get_single_install(app_name:"SecurityCenter", combined:TRUE, exit_if_unknown_ver:TRUE);
  sc_ver = install["version"];
}
if (! preg(pattern:"^4\.[6-9]", string:sc_ver)) audit(AUDIT_INST_VER_NOT_VULN, "SecurityCenter", sc_ver);

# Establish running of local commands
if ( islocalhost() )
{
  if ( ! defined_func("pread") ) audit(AUDIT_NOT_DETECT, "pread");
  info_t = INFO_LOCAL;
}
else
{
  sock_g = ssh_open_connection();
  if (! sock_g) audit(AUDIT_HOST_NOT, "able to connect via the provided SSH credentials.");
  info_t = INFO_SSH;
}

fix = "1.0.1j";
pattern = "OpenSSL (\d+(?:\.\d+)*(-beta\d+|[a-z]*))";

# Check version
line = info_send_cmd(cmd:"/opt/sc4/support/bin/openssl version");
if (info_t == INFO_SSH) ssh_close_connection();

if (! line) audit(AUDIT_VER_FAIL, "/opt/sc4/support/bin/openssl");
match = pregmatch(pattern:pattern, string:line);
if (isnull(match)) audit(AUDIT_UNKNOWN_APP_VER, line);
version = match[1];

# Check if vulnerable. Same branch only flags if the 1.0.1 matches,
# min check makes betas not vuln.
if (openssl_ver_cmp(ver:version, fix:fix, same_branch:TRUE, is_min_check:FALSE) < 0)
{
  report = '\n' +
    '\n  SecurityCenter version         : ' + sc_ver +
    '\n  SecurityCenter OpenSSL version : ' + version +
    '\n  Fixed OpenSSL version          : ' + fix +
    '\n';
  security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "OpenSSL (within SecurityCenter)", version);
