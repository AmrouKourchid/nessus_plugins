#TRUSTED 1001b8ea5614cae6110f1fd6c61d3d2c56e2f4172d5e270e2f55a887eac817325dbccf34cf3e1136876dfd9b7e827bbe46fb8cd874b4a0a644be2dcc03c260399b37eba3d65387575f049e91e292e0cca2671aceb4e7d4d4264d010c9d96324560bb2bd22c99df13299c927a07b373e48c1f800054db3fec2a5e48d399c99dcc61b7a53832598bc0856bf3c97e5050b01c3e305614894a5fa5c5c80f7fb8eb5bfe88ca40da16e5c29b61c5afe1bc4eac048b8bf06d9ba22d0eea108d5624b9b8e2c8409a3ecd444ff330cea84902c36618d6092068f7dc3c52dd000ece77411c805cada165cce0a7f011be85c52b4e59de79ede079fcca9ca76d4be43972e29c233689014baa951a5e783e5348135c219a93369e2ea5614a9a8fc6b2f9642966e13bbcc02dc728832745b62902048eafcb7f538f547a904e01fc6249577856d45e43b13851133c944292477d418cf4e6ba3891e928a6cdd8dc2411776e6f98bb8bb564050d5cd125873a93b1654c67915b67b2bb823df727bcbd33918f037b7612cac0e007a279e5714d9b140b4659c725491ae99956d62f3dacacaa62c03081a8eb8469c56579bcfd07812b89847b7a02a0c3cb3b8be21cc8a9c081988b0c6ab2bae08e11f81d43bfa942af229fe0c98b16f68d01d5a3d326bb2e70afb6dac53c59e21aac5412c0d325d6ef25ecb38afd1c681e2f9c6e8927b0f5e9c893de2d
#TRUST-RSA-SHA256 1f03929d1a3abfd18013755e49616e0b540d1e217ae299d5900f98b97ec0461a970effbfc8514b0b158ba6a8c377d241adb6a7f7e8ab627fbfe5a1ba4ebb145bd8ab7a6f4c0d38f93a43c3cd925c59ab86ffa7d110c62d0ef33f7359b219fbd3bca164ee6c74dbaef06129540b2ea7cd3e2aaf03a286de71f85c4f546770dfd0e5d0b598626a6b906fe40eda6701183fd9a2e82eb256217ca27e0132e12569415f6121aca4e2f09db81ed53286c3c9a3d547400e7cbe9a4d70212ba2343f24af0913abffa1d5d2034008b7d5f116aece6992b7a7c20f59cb53de3600f15e03efbd63e6e54276960d848f51d92236a0bc0119c56cf2a523e553d7dab24db8eb1a61a3ca292febdf8e8aced27fbae8e895b0902bd978216bbe45cf4e84d664a5acae1541661748d1479d9f60b669a17b13fcc5993cb862f5bf0347672c544c8df1aa2aa9f0ab5275e1e0c5d1a44f6dff84f286899b2dd68c4bb63e6885a9281d5fe77ebaf2a8c80c65a53a65ed5fd5cfc0a3f42fab477949da39ccae129f4b9f2dc69cfddbb2c2203819c19b6fb19ddc8b8e49428aeae2176d77152adea02f1018b33d6eb7c06b1cc499f4e5a494fd3f7c9c239c9546017280691f99ef6190f7940cb88ee33629c6c792c1afbacbf69dff5823984e1a7173b4b82a493064778677fd99631570fe647e2a2d70aad540aa3ef9217170a28701637df4099d06b854bf
#
# (C) Tenable Network Security, Inc.
#
# @@NOTE: The output of this plugin should not be changed
#
#
#

include("compat.inc");

if(description)
{
  script_id(10267);
  script_version("2.31");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/24");

  script_xref(name:"IAVT", value:"0001-T-0933");

  script_name(english:"SSH Server Type and Version Information");
  script_summary(english:"SSH Server type and version.");

  script_set_attribute(attribute:"synopsis", value:
"An SSH server is listening on this port.");
  script_set_attribute(attribute:"description", value:
"It is possible to obtain information about the remote SSH server by
sending an empty authentication request.");
  script_set_attribute(attribute:"risk_factor", value:"None" );
  script_set_attribute(attribute:"solution", value:"n/a" );

  script_set_attribute(attribute:"plugin_publication_date", value: "1999/10/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2002-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_require_ports("Services/ssh", 22);
  script_dependencies("find_service1.nasl", "find_service2.nasl", "external_svc_ident.nasl", "ssh_check_compression.nasl");

  exit(0);
}


#
# The script code starts here
#
include("ssh_lib.inc");

# This plugin uses the first SSH credential, not necessarily the
# correct SSH credential - authentication does not need to succeed
checking_default_account_dont_report = TRUE;

enable_ssh_wrappers();

if (get_kb_item("global_settings/supplied_logins_only"))
  supplied_logins_only = 1;
else
  supplied_logins_only = 0;

port = get_kb_item("Services/ssh");

if (!port) port = 22;
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port, "SSH");

version = NULL;
if (defined_func("bn_random"))
{
  var session = new('sshlib::session');
  if(!session.open_connection(port:port))
    audit(AUDIT_SOCK_FAIL, port, "SSH");

  var auth_method = "none";

  login = get_kb_item("Secret/SSH/login");
  if (isnull(login) && !supplied_logins_only)
    login = "n3ssus";

  session.get_supported_auth_methods(username:login, force:TRUE);

  version = session.remote_version;
  banner = session.userauth_banner;
  supported = join(session.supported_auth_methods, sep:",");
  key = session.remote_host_key;
  session.close_connection();
}

if ( empty_or_null(version) )
{
  soc = open_sock_tcp(port);
  if ( ! soc ) audit(AUDIT_SOCK_FAIL, port, "SSH");
  version = recv_line(socket:soc, length:4096);
  if ( !preg(pattern:"^SSH-", string:version ) ) audit(AUDIT_SERVICE_VER_FAIL, "SSH", port);
  close(soc);
}

if (!version) audit(AUDIT_SERVICE_VER_FAIL, "SSH", port);

set_kb_item(name:"SSH/banner/" + port, value:version);
text = "SSH version : " + version + '\n';

if (supported)
{
  set_kb_item(name:"SSH/supportedauth/" + port, value:supported);
  text += 'SSH supported authentication : ' + supported + '\n';
}

if (banner)
{
  set_kb_item(name:"SSH/textbanner/" + port, value:banner);
  text += 'SSH banner : \n' + banner + '\n';
}

if (key)
{
  fingerprint = hexstr(MD5(key));
  fingerprint_sha256 = hexstr(SHA256(key));
  b64_key = base64(str:key);

  if ("ssh-rsa" >< key)
  {
    set_kb_item(name:"SSH/Fingerprint/ssh-rsa/"+port, value:fingerprint);
    set_kb_item(name:"SSH/Fingerprint/sha256/ssh-rsa/"+port, value:fingerprint_sha256);
    set_kb_item(name:"SSH/publickey/ssh-rsa/"+port, value:b64_key);
  }
  else if ("ssh-dss" >< key)
  {
    set_kb_item(name:"SSH/Fingerprint/ssh-dss/"+port, value:fingerprint);
    set_kb_item(name:"SSH/Fingerprint/sha256/ssh-dss/"+port, value:fingerprint_sha256);
    set_kb_item(name:"SSH/publickey/ssh-dss/"+port, value:b64_key);
  }
  else if("ecdsa" >< key)
  {
    set_kb_item(name:"SSH/Fingerprint/ecdsa/"+port, value:fingerprint);
    set_kb_item(name:"SSH/Fingerprint/sha256/ecdsa/"+port, value:fingerprint_sha256);
    set_kb_item(name:"SSH/publickey/ecdsa/"+port, value:b64_key);
  }
}

report = '\n' + text;

security_note(port:port, extra:report);
register_service(port:port, proto: "ssh");
