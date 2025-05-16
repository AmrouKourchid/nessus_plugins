#TRUSTED 038e4322aa79f6db2c908d1ffcb710680a411549469dbfdf415205303c8502a57c19bcecec0cf5f3c723a1d36d39c0c14d4e6606b3b363e9ce90436319613fcbff13e8201a261c0cb59fe6ec5471fcd405e8063a7b0a40bc7841ad1e9c99241c2d4accc3a2321505d1da408fa3f3a8069645fbad8c6c2dc663f8a062d30cd0df04d24a9aa55320ecab4226e32589b84e6834af94e5fe54f07fca1c93e864dd087384ec99c0195f16ca5fdd925f19c79d649830aad80ea8a46fd7edae82a8c3deeac9468eac84fb65314b12611590b4ca1c602a68f169313234e3d7915145aa5e63f4cc16b2f5c79eb229096866b0eb8896cb7a6fcef6b5c5fe920e3bcf641a7bae89e62a7f0880b8abb9554dcb1ca7e92b38696c4a7eee1566cefefff3af652d97336a76b083f0306761d1b42bb756023e9b6b7fb244e93f2dce89d4e7893adbb200cfd8a8e64ba3a74cf8f5e6879ccd0022b4aa6b0ce0b36ee014553a6d23fc59dda2d9626d211470017d7b2c878de9cf281ad48928a881133ce7116002accc4579ec5c8dfed85ed721777f40b67e2a12af11d7b3f1c202b0154a3c7e5b38db4f065fa44e935729a919c5c6f319bf0c6fca12b75c019c6aee3d31cae21fa4c6dfb39021bb44bef7edc796660b05264bd6ddd7333d86b6608522a3c8b97d79c03353d557335592ae66c71a23a7ac92aa0faf0a654ee32ad152842669982d7ef0
#TRUST-RSA-SHA256 6359230b2e45fa5980a70fe6ecb9b1b3fcda46bc239b6d84b062d59f8c96df3839c31e5ba4d58c06d11c138ec9984d3c94b187efcd4754dcb15fadb98d60262037398b9bbc8a7fcb648f0b7eab173b6aa4c903faf622d0ad38a517b34e4968d3fb812f70b309af63f5be8a38c51d2b80dd9958f99fdc0256d49975c7d0b0b1f25b4086da262f1673c1b074e6c67f47806d1b336e65415c72326c39e54f5a4b5631b4ad91d510c34b9160a1e97455a6bcbf790feedd47d0334ee2087d0cc8eedde0b103667e6acabb281b1e46f43de9fc544312d795c8a15c4909d16aee31ca5e8e808a5e2d6be49fd253ac8bacc2741c32ed8f7f54eac6b338f31bc7624bddc5a425fd136ea872aeb3b68022d89ca285685aab0d24cd7bd257e8d541dc0d8c13407f75ef9d21a8b491cc08efc70afd391c5120fe0c8362d74dff852ce27907db126fe0a283e630c9b0b78d548ba572cb79a05c201a59fff040ed717daf3b0d6d301c49f59507479a1cbc4d9f196fe3ac556f8b5b757a9dc9e0372c68a6a78f71d72f4b52e02ff2bef3a6face18f204efdda68e5cefbc155ae1932b55ef27e629b8433b9ca685f309d630a5335d4f623b105ade4ea76217a8a7bae2d337e624432619afe162fd39e5bd077d69331531f9d9a17ac53c6aa6e7446b2a410c5f5bceff41acd1ee9184af2de335d64b3e1ec58928060bff64f5f81d7d7fe1e778fc47
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87762);
  script_version("1.25");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_cve_id("CVE-2015-6934");
  script_bugtraq_id(79648);
  script_xref(name:"VMSA", value:"2015-0009");
  script_xref(name:"IAVB", value:"2016-B-0006");
  script_xref(name:"CERT", value:"576313");

  script_name(english:"VMware vCenter / vRealize Orchestrator Appliance 4.2.x / 5.x / 6.x Java Object Deserialization RCE (VMSA-2015-0009)");
  script_summary(english:"Checks the version of VMware vCenter/vRealize Orchestrator Appliance.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a virtualization appliance installed that is
affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of VMware vCenter / vRealize Orchestrator Appliance
installed on the remote host is 4.2.x or 5.x or 6.x and includes the
Apache Commons Collections (ACC) library version 3.2.1. It is,
therefore, affected by a remote code execution vulnerability due to
unsafe deserialize calls of unauthenticated Java objects to the ACC
library. An unauthenticated, remote attacker can exploit this, by
sending a crafted request, to execute arbitrary code on the target
host.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2015-0009.html");
  script_set_attribute(attribute:"see_also", value:"https://kb.vmware.com/selfservice/microsites/search.do?cmd=displayKC&externalId=2141244");
  # https://blogs.apache.org/foundation/entry/apache_commons_statement_to_widespread
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?91868e8b");
  # https://foxglovesecurity.com/2015/11/06/what-do-weblogic-websphere-jboss-jenkins-opennms-and-your-application-have-in-common-this-vulnerability/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9c6d83db");
  script_set_attribute(attribute:"see_also", value:"https://www.infoq.com/news/2015/11/commons-exploit");
  script_set_attribute(attribute:"solution", value:
"Apply the patch referenced in VMware KB 2141244.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-6934");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vcenter_orchestrator");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vrealize_orchestrator");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/VMware vCenter Orchestrator/Version", "Host/VMware vCenter Orchestrator/VerUI", "Host/VMware vCenter Orchestrator/Build", "HostLevelChecks/proto", "Host/local_checks_enabled");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");


enable_ssh_wrappers();

version = get_kb_item_or_exit("Host/VMware vCenter Orchestrator/Version");
verui = get_kb_item_or_exit("Host/VMware vCenter Orchestrator/VerUI");

proto = get_kb_item_or_exit('HostLevelChecks/proto');
get_kb_item_or_exit("Host/local_checks_enabled");

if (proto == 'local')
  info_t = INFO_LOCAL;
else if (proto == 'ssh')
{
  info_t = INFO_SSH;
  ret = ssh_open_connection();
  if (!ret) audit(AUDIT_FN_FAIL, 'ssh_open_connection');
}
else
  exit(0, 'This plugin only attempts to run commands locally or via SSH, and neither is available against the remote host.');

app_name = "VMware vCenter/vRealize Orchestrator Appliance";

if (version !~ "^4\.2($|\.)" && version !~ "^5\." && version !~ "^6\.")
  audit(AUDIT_INST_VER_NOT_VULN, app_name, verui);

# if any of these files exist, we are vulnerable
# /var/lib/vco/app-server/deploy/vco/WEB-INF/lib/commons-collections-3.2.1.jar
# /var/lib/vco/configuration/lib/o11n/commons-collections-3.2.1.jar
# /opt/vmo/app-server/server/vmo/lib/commons-collections.jar
# /opt/vmo/configuration/jetty/lib/ext/commons-collections.jar

file1 = "/var/lib/vco/app-server/deploy/vco/WEB-INF/lib/commons-collections-3.2.1.jar";
file2 = "/var/lib/vco/configuration/lib/o11n/commons-collections-3.2.1.jar";
file3 = "/opt/vmo/app-server/server/vmo/lib/commons-collections.jar";
file4 = "/opt/vmo/configuration/jetty/lib/ext/commons-collections.jar";

file1_exists = info_send_cmd(cmd:"ls " + file1 + " 2>/dev/null");
file2_exists = info_send_cmd(cmd:"ls " + file2 + " 2>/dev/null");
file3_exists = info_send_cmd(cmd:"ls " + file3 + " 2>/dev/null");
file4_exists = info_send_cmd(cmd:"ls " + file4 + " 2>/dev/null");

if(info_t == INFO_SSH) ssh_close_connection();

if (empty_or_null(file1_exists) && empty_or_null(file2_exists) && empty_or_null(file3_exists) && empty_or_null(file4_exists))
  audit(AUDIT_INST_VER_NOT_VULN, app_name, verui);

report = '\n  Installed version  : ' + verui;
if (!empty_or_null(file1_exists))
  report += '\n  Vulnerable library : ' + file1;
if (!empty_or_null(file2_exists))
  report += '\n  Vulnerable library : ' + file2;
if (!empty_or_null(file3_exists))
  report += '\n  Vulnerable library : ' + file3;
if (!empty_or_null(file4_exists))
  report += '\n  Vulnerable library : ' + file4;
report +=  '\n';

security_report_v4(port:0, severity:SECURITY_HOLE, extra:report);
