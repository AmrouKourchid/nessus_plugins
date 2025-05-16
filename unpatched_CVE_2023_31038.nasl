#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(226714);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2023-31038");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2023-31038");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - SQL injection in Log4cxx when using the ODBC appender to send log messages to a database. No fields sent
    to the database were properly escaped for SQL injection. This has been the case since at least version
    0.9.0(released 2003-08-06) Note that Log4cxx is a C++ framework, so only C++ applications are affected.
    Before version 1.1.0, the ODBC appender was automatically part of Log4cxx if the library was found when
    compiling the library. As of version 1.1.0, this must be both explicitly enabled in order to be compiled
    in. Three preconditions must be met for this vulnerability to be possible: 1. Log4cxx compiled with ODBC
    support(before version 1.1.0, this was auto-detected at compile time) 2. ODBCAppender enabled for logging
    messages to, generally done via a config file 3. User input is logged at some point. If your application
    does not have user input, it is unlikely to be affected. Users are recommended to upgrade to version 1.1.0
    which properly binds the parameters to the SQL statement, or migrate to the new DBAppender class which
    supports an ODBC connection in addition to other databases. Note that this fix does require a
    configuration file update, as the old configuration files will not configure properly. An example is shown
    below, and more information may be found in the Log4cxx documentation on the ODBCAppender. Example of old
    configuration snippet: <appender name=SqlODBCAppender class=ODBCAppender> <param name=sql
    value=INSERT INTO logs (message) VALUES ('%m') /> ... other params here ... </appender> The migrated
    configuration snippet with new ColumnMapping parameters: <appender name=SqlODBCAppender
    class=ODBCAppender> <param name=sql value=INSERT INTO logs (message) VALUES (?) /> <param
    name=ColumnMapping value=message/> ... other params here ... </appender> (CVE-2023-31038)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-31038");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info2.nasl");
  script_require_keys("Host/cpu", "Host/local_checks_enabled", "global_settings/vendor_unpatched");
  script_require_ports("Host/Debian/dpkg-l", "Host/Debian/release");

  exit(0);
}
include('vdf.inc');

# @tvdl-content
var vuln_data = {
 "metadata": {
  "spec_version": "1.0p"
 },
 "requires": [
  {
   "scope": "scan_config",
   "match": {
    "vendor_unpatched": true
   }
  },
  {
   "scope": "target",
   "match": {
    "os": "linux"
   }
  }
 ],
 "report": {
  "report_type": "unpatched"
 },
 "checks": [
  {
   "product": {
    "name": [
     "liblog4cxx-dev",
     "liblog4cxx-doc",
     "liblog4cxx15"
    ],
    "type": "dpkg_package"
   },
   "check_algorithm": "dpkg",
   "constraints": [
    {
     "requires": [
      {
       "scope": "target",
       "match": {
        "distro": "debian"
       }
      },
      {
       "scope": "target",
       "match": {
        "os_version": "12"
       }
      }
     ]
    }
   ]
  },
  {
   "product": {
    "name": [
     "liblog4cxx-dev",
     "liblog4cxx-doc",
     "liblog4cxx11"
    ],
    "type": "dpkg_package"
   },
   "check_algorithm": "dpkg",
   "constraints": [
    {
     "requires": [
      {
       "scope": "target",
       "match": {
        "distro": "debian"
       }
      },
      {
       "scope": "target",
       "match": {
        "os_version": "11"
       }
      }
     ]
    }
   ]
  }
 ]
};

var vdf_res = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_HOLE);
vdf::handle_check_and_report_errors(vdf_result: vdf_res);
