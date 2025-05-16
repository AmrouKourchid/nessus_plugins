#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(22869);
  script_version("1.36");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/26");

  script_xref(name:"IAVT", value:"0001-T-0502");

  script_name(english:"Software Enumeration (SSH)");
  script_summary(english:"Displays the list of packages installed on the remote system.");

  script_set_attribute(attribute:"synopsis", value:
"It was possible to enumerate installed software on the remote host via
SSH.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to list the software installed on the remote host by
calling the appropriate command (e.g., 'rpm -qa' on RPM-based Linux
distributions, qpkg, dpkg, etc.).");
  script_set_attribute(attribute:"solution", value:
"Remove any software that is not in compliance with your organization's
acceptable use and security policies.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"agent", value:"unix");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2006-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "macosx_eval_installed.nbin");
  script_require_keys("Host/uname");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

function report(os, buf)
{
  var report = '';
  var line;

  if (buf =~ '[^ \t\r\n]') 
  {
    report += '\nHere is the list of packages installed on the remote ' + os + ' system :\n\n';

    # Split buf on newline and throw away the '\n'. If there are multiple newlines together, like '\n\n', we want 
    # to end up with list items that are just empty strings, which we will deal with in the foreach loop below
    # Avoid sorting the results with sort(), which could be multiline
    buf = split(buf, sep:'\n', keep:0);

    foreach line (buf)
    {
      # remove leading/trailing spaces
      line = chomp(line);
      line = preg_replace(pattern:"^[\s]+" , replace:'' , string:line );

      if (line)
      {
        report += '  ' + line + '\n';
      }
    }
  }

  else
  {
    report += '\nThere are no packages installed on the remote ' + os + ' system.\n';
  }

  # security_note(port:0, extra:report);
  security_report_v4(port:0, severity:SECURITY_NOTE , extra:report);
}

var list = make_array(
  "Host/AIX/lslpp",                   "AIX",
  "Host/Alibaba/rpm-list",            "Alibaba Linux",
  "Host/AlmaLinux/rpm-list",          "Alma Linux",
  "Host/AmazonLinux/rpm-list",        "Amazon Linux",
  "Host/CBLMariner/rpm-list",         "CBL-Mariner",
  "Host/CentOS/rpm-list",             "CentOS Linux",
  "Host/Debian/dpkg-l",               "Debian Linux",
  "Host/EulerOS/rpm-list",            "EulerOS",
  "Host/FreeBSD/pkg_info",            "FreeBSD",
  "Host/Gentoo/qpkg-list",            "Gentoo Linux",
  "Host/HP-UX/swlist",                "HP-UX",
  "Host/JunOS/pkg_info",              "Juniper JunOS",
  "Host/Junos_Space/rpm-list",        "Juniper Junos Space",
  "Host/KylinOS/rpm-list",            "KylinOS Server Linux",
  "Host/KylinOS/dpkg-l",              "KylinOS Desktop Linux",
  "Host/MacOSX/InstalledSW",          "Mac OS X",
  "Host/Mandrake/rpm-list",           "Mandriva Linux",
  "Host/McAfeeLinux/rpm-list",        "McAfee Linux",
  "Host/OracleVM/rpm-list",           "OracleVM",
  "Host/PhotonOS/rpm-list",           "VMware PhotonOS",
  "Host/RedHat/rpm-list",             "Red Hat Linux",
  "Host/RockyLinux/rpm-list",         "Rocky Linux",
  "Host/Slackware/packages",          "Slackware Linux",
  "Host/Solaris/showrev",             "Solaris",
  "Host/Solaris11/pkg-list",          "Solaris 11",
  "Host/Sophos UTM/rpm-list",         "Sophos UTM",
  "Host/SuSE/rpm-list",               "SuSE Linux",
  "Host/TencentOS/rpm-list",          "Tencent OS",
  "Host/TrendMicro/IWSVA/rpm-list",   "Trend Micro IWSVA",
  "Host/VMware/esxupdate",            "VMware ESXi / ESX",
  "Host/VMware/esxcli_software_vibs", "VMware ESXi / ESX",
  "Host/XenServer/rpm-list",          "Citrix XenServer",
  "Host/Virtuozzo/rpm-list",          "Virtuozzo Linux",
  "Host/Zscaler/pkg_info",            "Zscaler",
  "Host/ZTE-CGSL/rpm-list",           "Carrier Grade Server Linux"
);

var item, buf;
for (item in list) 
{
  buf = get_kb_item(item);

  if ( buf ) 
  {
    # Write the Host/nix/packages KB key before potentially replacing the output with
    # a version that has date strings within.
    replace_kb_item(name:'Host/nix/packages', value:buf);

    # Check for a version listing the dates, if applicable.
    # Example: Host/EulerOS/rpm-list or Host/EulerOS/rpm-list-date
    var date_listed = get_kb_item(item + "-date");

    if (!empty_or_null(date_listed))
    {
      buf = date_listed;
    }

    report(os:list[item], buf:buf);
  }
}
