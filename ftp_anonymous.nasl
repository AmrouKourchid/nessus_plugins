#TRUSTED 9511d398c8c1d5f6cf41882a62e1e14033b54afa0958d40bf84e584722733a3f5f1f536db843b890935d1406c7403f6be593e53a4842b998ab5deb4e78c886e4617db3aa26efcdde1a706a2b527e2913c4a941ddb2b6e4ac87795858328f8e193c67157f158f6f328ec42a0f4298bf207dc7177fec81b542ce3b8d6bcc04a651eb065b97a329ede9d971cffd0808f29f302afe6af64b9c4ca6a585200025a6c68c83bfe7d24efd449731c9f339a78ea99668fc6cd9a813f1a5bac3bd14c3d35ac2ec69fe496fc52f2c230c15e98d91871f7372b925fc863908f16d81be015a3c95e139252a843de7f120ae41eb6aad83231d89c4b2971ad08d24477c19fd78cfa411c250f7f5f385a79a8e0e0fcb40cc4bea1f9dd4459b97a68865cbbbab32a9e820c363a31ab82b71d60a05822696f66c519ee9018bf941125fa3c683bca6e2fff8808389686046620f4f9bf440e1427a04dec2fca12ec03e885d4dd3d1c4a1997a23dd24f7be37a32afd84e4296620332c884a34c5df63d2d05e2c2cf81e0c6a5b70a6cfd815ec82d9eec4181a27bab75e5fc09b0ce6e6ebf542116d8c0f14be213cef845fc7347dec25a93fd273cf775a6169e75ec949552de0a03fe558173658056c4484fc090a133b127646c98b344d297ea975930768a4eb66608c24d0e035fbad3c3f71f3fb14f9c46bf383a728c9ff1a2ea242758406a5cf3e50c213
#TRUST-RSA-SHA256 402aa35346a7ad6f72aec29ffc49219841d62297d4e873d3603bfbe29ce9c90343dabe7a85e9da2de30579a668f836d2c6499f9e874be748d0b5ae339baaaae4cbb782b17c6734704252af5ec90bc42d6052ec92bc3f4c6a332e1cf6b3caf86acf2404646406ead3b6469024b3cd427bb97175ec6ec97bbe83c0bbd2193482c86ffd9e690aaad3b8002914f44ac42bf0a51a9150737778699f097ba08674be88dd6b8172908f056686082b747fa1a3afd32579c5fe148d8c2bb7d33ac7a87f32b71f0494219e87fc752a0d44081ce259c9d7cfb6a11bdfda11dace6e0802de8baa8ecc01e9e78113f5f598e36dfb8a98ec60c6d8d42226839af598cdc657ff80fe807090ff700a4609604d2a57188bd527e35c7167411b1b993c69a11f5c726e3382677372dd621ab3c7dae65713a8cab005745472fca0acd04f1f9b54a8ed387e1183734e7a095b0b74035b53f6a0949611f84b054aae55db4c8af922683d8c953e8f8c855aadad4b9db31e26240e2fd2823add9e5cbbaf9e9c9b8dad14dce7f73acd6cab48754f5540c2c475b5e354f2a37fc5956335a7a4aac1c09c84940b22b56dcf92e8a261d84c51109dcc0083c9ce57a99a6a211ccc2dc497e1baec3be3ba8bd23067f3b259f5f89a2cc792c0667feea7c35a78760fd645ec28182389e1d5c02321af2b967c696d3285e7f58eda5527bbb3cf1ca4f3cb4cae438658c6
###
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10079);
 script_version("1.60");
 script_set_attribute(attribute:"plugin_modification_date", value:"2023/08/16");

 script_cve_id("CVE-1999-0497");
 script_bugtraq_id(83206);

 script_name(english:"Anonymous FTP Enabled");
 script_summary(english:"Checks if the remote ftp server accepts anonymous logins.");

 script_set_attribute(attribute:"synopsis", value:
"Anonymous logins are allowed on the remote FTP server.");
 script_set_attribute(attribute:"description", value:
"Brute force setting must be enabled to use this plugin.

Nessus has detected that the FTP server running on the remote host
allows anonymous logins. Therefore, any remote user may connect and
authenticate to the server without providing a password or unique
credentials. This allows the user to access any files made available
by the FTP server.");
 script_set_attribute(attribute:"solution", value:
"Disable anonymous FTP if it is not required. Routinely check the FTP
server to ensure that sensitive content is not being made available.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");

  script_set_attribute(attribute:"cvss_score_source", value:"CVE-1999-0497");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Tenable gives a Confidentiality impact of Partial since the issue could allow unwanted access to file system.");
 script_set_attribute(attribute:"vuln_publication_date", value:"1993/07/01");
 script_set_attribute(attribute:"plugin_publication_date", value:"1999/06/22");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"FTP");

 script_copyright(english:"This script is Copyright (C) 1999-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

 script_dependencies("logins.nasl", "ftpserver_detect_type_nd_version.nasl");
 script_exclude_keys("global_settings/supplied_logins_only");
 script_require_ports("Services/ftp", 21);

 exit(0);
}

include("audit.inc");
include("ftp_func.inc");
include("global_settings.inc");

port = get_ftp_port(default: 21, broken:TRUE);

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);


anon_accts = make_list(
  'anonymous',
  'ftp'
);

pass = "nessus@nessus.org";

foreach acct (anon_accts)
{
  soc = open_sock_tcp(port);
  if (soc)
  {
    r = ftp_authenticate(socket:soc, user:acct, pass:pass, port:port);
    if (r)
    {
      port2 = ftp_pasv(socket:soc);
      if (port2)
      {
        soc2 = open_sock_tcp(port2, transport:get_port_transport(port));
        if (soc2)
        {
          send(socket:soc, data:'LIST\r\n');
          listing = ftp_recv_listing(socket:soc2);
          close(soc2);
        }
      }

      if (strlen(listing))
      {
        report = 'The contents of the remote FTP root are :\n' + listing;
      }

      if (report) security_warning(port:port, extra: report);
      else security_warning(port);

      set_kb_item(name:"ftp/anonymous", value:TRUE);
      set_kb_item(name:"ftp/"+port+"/anonymous", value:TRUE);
      user_password = get_kb_item("ftp/password");
      if (!user_password)
      {
        if (! get_kb_item("ftp/login"))
          set_kb_item(name:"ftp/login", value:acct);
        set_kb_item(name:"ftp/password", value:pass);
      }
      close(soc);
      exit(0);
    }
    close(soc);
  }
}
