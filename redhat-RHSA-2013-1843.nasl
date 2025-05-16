#TRUSTED 470d68fecbba3c4d4ad0b0a8502236e818bd0f23fa6cce8414b093747fed2eb25df2ad7b3a298490f18aa40b765f1b62b36aa38bcb0d1adbc106045fbc6e42a7f42c23f83cd755916c469cd39a38d2ec0615477598d151c22ab7730c62fde007ea0f205a3921ff47ad8abe2fdeb6be7ee651e5c826d37ef9f5de1dc7864d0e7f0bf5e786a3270c33f9ddcc1e022738b4da911f7a7963633344a512b240c3b2e0e3698f555d9a4b53c57a421d9f18fdcec0a74947c7bd64eb4774e1672007e82214f54f7de376cd62f93b1c03c81be63bac84b5493fea9b286556b7e2da3cc5103cfd3d50da1425e8a4088351fa96a1366895d8240904c1820cf0bb780b56fb70b716a0d8ac8fbbe03c80612f8c349cb8dc913def83f3e5e88d47f1c42085fb54aefec4e79f7afc1b8c9a3749b32658ff5cbf8970794da644a2d3632dc56e37ac05ff805e7f7c2d1fdda73a8aa6607f07efa2384fa65561c429a7e7c044aee19f5ffb1134689bd78751c9443d0891870f372115ee47fd0cc9bcc0a9f293b62e55911eec44744be1813947ea1faeb12ee348942098d1464bbb1cd081644eb8d1c68f79ff8b587282ad8b2898111e4936c52e6d3825a408bfc3bccd5b1be9828e1008644ef5345cfad3a52ba6d227e863cd673c0ebd5edf966d5c2201497552b66acc2beda527ac41cc34ca2fe8f0a588897015963cb5d61cc151ca221b54753a2e
#TRUST-RSA-SHA256 6e1b272e2e72577bc0b70f56c01b2b7f30ae2c4b1d091fee684f88253305e4b8d27ff975dc70685822c82532c821dcace808d3774fa107fa24b163900afe7ee81065e44c36138fc6e0ef72742e292ae23e37b6eb6c55c906f3880bb852c79adf50d94db8728f8e9cb5f453b74a25329e4b66eaf7650ae1be12159729a9fdef058b4ce40085ee608a4c4215a321ba35ddb2d0ca0166e4ef026f134193fc3257d8d70cb778c06c8609784397776af01c395345c3e54ef0faef7b1bb2ed5395c10c9e15a1385bba3380f790e7d35346a27064fa822a81c98e389f516ee77b5f736c79077ebf0fa34c3c1e994c8547163045eea36b4a34706492468731adeb0519a85eed9e2200629dd74abc56b1bb5b80b1e407b4ea1d37f657ff263503ec947c24e858563048bbd7e0fb4c93cc6345f5defb68e89f1cddc545988fc88f183a486f24eede5d45ab265f6d0046f03ea7287639d24735f07e0fa280db63aa3c5b15f2c0b989edeb2dcec3d8940c9c36790cb31d86162d7de0b773bd7ce2818d698ba8bc1ef1fae6ff4d7920ab68e2dfaa83f932cfd48711b2b573c28c784a324b4245078502a5fb8859664432b17f0c9eb7d73317fd9abfd2f1786545e3fd24aa0380e4bf7957827b47ce60f5574eb87dbba854c8c661db1615e521795cbc2d40a20525c39641a473806b86394a40382524b1474a5b08e142ece53bdbc8c298120a79
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(72390);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_cve_id("CVE-2013-4424");
  script_bugtraq_id(64365);
  script_xref(name:"RHSA", value:"2013:1843");

  script_name(english:"Red Hat JBoss Enterprise Application Platform 6.1.0 Security Update (RHSA-2013:1843)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of JBoss Enterprise Application Platform running on the
remote system is affected by multiple cross-site scripting flaws in
the GateIn Portal component. This could allow a remote attacker to
manipulate a logged in user into visiting a specially crafted URL,
thereby executing an arbitrary web script in the context of the user's
GateIn Portal session.");
  script_set_attribute(attribute:"see_also", value:"https://www.redhat.com/security/data/cve/CVE-2013-4424.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate JBoss Enterprise Application Platform 6.1.0
security update.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-4424");
  
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/12/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:redhat:jboss_enterprise_application_platform");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2023 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl", "jboss_detect.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/JBoss/EAP");

  exit(0);
}

include("ssh_func.inc");
include("telnet_func.inc");
include("local_detection_nix.inc");
include("hostlevel_funcs.inc");
include("datetime.inc");


enable_ssh_wrappers();

# We are only interested in Red Hat systems
if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");

installs = get_kb_list_or_exit("Host/JBoss/EAP");

info_connect(exit_on_fail:TRUE);

info = "";
jboss = TRUE;
invalid_path = FALSE;

foreach var install (make_list(installs))
{
  match = eregmatch(string:install, pattern:"([^:]+):(.*)");

  if (!isnull(match))
  {
    ver = match[1];
    path = match[2];

    if (path =~ INJECTION_PATTERN)
    {
      invalid_path = TRUE;
      continue;
    }

    # check for install version = 6.1.0
    if (ver =~ "^6.1.0([^0-9]|$)")
    {
      # check that the target file exists
      cmd = 'test -f "$1$modules/system/layers/base/org/jboss/ejb-client/main/jboss-ejb-client-1.0.21.Final-redhat-1.jar" && echo FOUND';
      buf = ldnix::run_cmd_template_wrapper(template:cmd, args:[path]);
      if ( (buf) && ("FOUND" >< buf) )
      {
        # extract the needed line from the file
        cmd = 'unzip -p $1$modules/system/layers/base/org/jboss/ejb-client/main/jboss-ejb-client-1.0.21.Final-redhat-1.jar META-INF/MANIFEST.MF | grep "Build-Timestamp"';
        buf = ldnix::run_cmd_template_wrapper(template:cmd, args:[path]);
        if ( (buf) )
        {
          # parse the line into the needed date portions
          match = eregmatch(string:buf, pattern:"Build-Timestamp: [^,]+,\s+(\d+)\s+([A-Za-z]+)\s+(\d+)");

          if (!isnull(match))
          {
            day = match[1];
            month = month_num_by_name(match[2], base:1);
            year = match[3];

            # compare the dates to see if it is older than the patch
            if (ver_compare(ver:year+"."+month+"."+day, fix:"2013.11.27") < 0)
            {
              info += '\n' + '  Path    : ' + path+ '\n';
              info += '  Version : ' + ver + '\n';
            }
          }
        }
      }
    }
  }
}

if (info_t == INFO_SSH) ssh_close_connection();

errors = "";
if(invalid_path)
{
  errors = '\nResults may not be complete due to the following errors : ';
  errors += '\n  The path name: "' + path + '" contained invalid characters.';
}

# Report what we found.
if (info)
{
  set_kb_item(name:'www/0/XSS', value:TRUE);
  if (report_verbosity > 0)
  {
    if (max_index(split(info)) > 3) s = 's of JBoss Enterprise Application Platform are';
    else s = ' of JBoss Enterprise Application Platform is';

    report =
      '\n' +
      'The following instance'+s+' out of date and\nshould be patched or upgraded as appropriate :\n' +
      info +
      '\n' + errors;

    security_warning(port:0, extra:report);
  }
  else security_warning(port:0);
}
else if ( (!info) && (jboss) )
{
  exit(0, "The JBoss Enterprise Application Platform version installed is not affected." + errors);
}
else audit(AUDIT_HOST_NOT, "affected");
