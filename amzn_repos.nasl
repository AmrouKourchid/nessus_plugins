##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(212053);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/04");

  script_name(english:"Amazon Linux : Enabled Official Repositories and Extras");
  script_summary(english:"Reports the Amazon Linux repositories and extras enabled on the host.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote host is using one or more Amazon Linux repositories to install packages."
  );
  script_set_attribute(
    attribute:"description",
    value:"The remote host is using one or more Amazon Linux repositories to install packages.
    These repositories may be used in conjuntion with Amazon Linux OS package level assessment
    security advisories to determine whether or not relevant repositories are installed before
    checking package versions for vulnerable ranges."
  );
  # https://docs.aws.amazon.com/linux/al2/ug/al2-extras-list.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?804d18c7");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_type", value:"local");

  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/04");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Amazon Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled");

  exit(0);
}

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

# Check for repos and extras keys
var host_repo_list = get_kb_list("Host/AmazonLinux/enabled_repos_label");
var host_extras_list = get_kb_list("Host/AmazonLinux/enabled_extras_label");

if(empty_or_null(host_repo_list) && empty_or_null(host_extras_list)) audit(AUDIT_NOT_INST, "An Amazon Linux repository");

var repos_block = '';
var extras_block = '';
var report = '';
var i;

# Itemize repos
if(!empty_or_null(host_repo_list))
{
  host_repo_list = sort(host_repo_list);
  for (i = 0; i < max_index(host_repo_list); i++)
  {
    repos_block += '  ' + host_repo_list[i] + '\n';
  }
}
# Itemize extras 
if(!empty_or_null(host_extras_list))
{
  host_extras_list = sort(host_extras_list);
  for (i = 0; i < max_index(host_extras_list); i++)
  {
    extras_block += '  ' + host_extras_list[i] + '\n';
  }
}

if (!empty_or_null(repos_block))
  report += 'Amazon Linux Repositories found to be enabled:\n' + repos_block + '\n';

if (!empty_or_null(extras_block))
  report += 'Amazon Linux Extras found to be enabled:\n' + extras_block + '\n';


security_report_v4(
  port       : 0,
  severity   : SECURITY_NOTE,
  extra      : report
);
