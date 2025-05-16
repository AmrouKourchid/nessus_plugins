#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(224238);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2021-43809");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2021-43809");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - `Bundler` is a package for managing application dependencies in Ruby. In `bundler` versions before 2.2.33,
    when working with untrusted and apparently harmless `Gemfile`'s, it is not expected that they lead to
    execution of external code, unless that's explicit in the ruby code inside the `Gemfile` itself. However,
    if the `Gemfile` includes `gem` entries that use the `git` option with invalid, but seemingly harmless,
    values with a leading dash, this can be false. To handle dependencies that come from a Git repository
    instead of a registry, Bundler uses various commands, such as `git clone`. These commands are being
    constructed using user input (e.g. the repository URL). When building the commands, Bundler versions
    before 2.2.33 correctly avoid Command Injection vulnerabilities by passing an array of arguments instead
    of a command string. However, there is the possibility that a user input starts with a dash (`-`) and is
    therefore treated as an optional argument instead of a positional one. This can lead to Code Execution
    because some of the commands have options that can be leveraged to run arbitrary executables. Since this
    value comes from the `Gemfile` file, it can contain any character, including a leading dash. To exploit
    this vulnerability, an attacker has to craft a directory containing a `Gemfile` file that declares a
    dependency that is located in a Git repository. This dependency has to have a Git URL in the form of
    `-u./payload`. This URL will be used to construct a Git clone command but will be interpreted as the
    upload-pack argument. Then this directory needs to be shared with the victim, who then needs to run a
    command that evaluates the Gemfile, such as `bundle lock`, inside. This vulnerability can lead to
    Arbitrary Code Execution, which could potentially lead to the takeover of the system. However, the
    exploitability is very low, because it requires a lot of user interaction. Bundler 2.2.33 has patched this
    problem by inserting `--` as an argument before any positional arguments to those Git commands that were
    affected by this issue. Regardless of whether users can upgrade or not, they should review any untrustred
    `Gemfile`'s before running any `bundler` commands that may read them, since they can contain arbitrary
    ruby code. (CVE-2021-43809)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-43809");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info2.nasl");
  script_require_keys("Host/cpu", "Host/local_checks_enabled", "global_settings/vendor_unpatched");
  script_require_ports("Host/Debian/dpkg-l", "Host/Debian/release", "Host/RedHat/release", "Host/RedHat/rpm-list");

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
     "bundler",
     "ruby-bundler",
     "ruby-rubygems"
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
  },
  {
   "product": {
    "name": "rubygem-bundler",
    "type": "rpm_package"
   },
   "check_algorithm": "rpm",
   "constraints": [
    {
     "requires": [
      {
       "scope": "target",
       "match": {
        "distro": "redhat"
       }
      },
      {
       "scope": "target",
       "match": {
        "os_version": "8"
       }
      }
     ]
    }
   ]
  },
  {
   "product": {
    "name": "ruby",
    "type": "rpm_package"
   },
   "check_algorithm": "rpm",
   "constraints": [
    {
     "requires": [
      {
       "scope": "target",
       "match": {
        "distro": "redhat"
       }
      },
      {
       "scope": "target",
       "match": {
        "os_version": "8"
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
