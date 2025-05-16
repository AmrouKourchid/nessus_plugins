#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2024:1639-2. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(201225);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/02");

  script_cve_id("CVE-2023-28858", "CVE-2023-28859");
  script_xref(name:"SuSE", value:"SUSE-SU-2024:1639-2");

  script_name(english:"SUSE SLED15 / SLES15 / openSUSE 15 Security Update : python-arcomplete, python-Fabric, python-PyGithub, python-antlr4-python3-runtime, python-avro, python-chardet, python-distro, python-docker, python-fakeredis, python-fixedint, python-httplib2, python-httpretty, python-javaproperties, python-jsondiff, python-knack, python-marshmallow, python-opencensus, python-opencensus-context, python-opencensus-ext-threading, python-opentelemetry-api, python-opentelemetry-sdk, python-opentelemetry-semantic-conventions, python-opentelemetry-test-utils, python-pycomposefile, python-pydash, python-redis, python-retrying, python-semver, python-sshtunnel, python-strictyaml, python-sure, python-vcrpy, python-xmltodict (SUSE-SU-2024:1639-2)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED15 / SLED_SAP15 / SLES15 / SLES_SAP15 / openSUSE 15 host has packages installed that are
affected by multiple vulnerabilities as referenced in the SUSE-SU-2024:1639-2 advisory.

    This update for python-argcomplete, python-Fabric, python-PyGithub, python-antlr4-python3-runtime, python-
    avro, python-chardet, python-distro, python-docker, python-fakeredis, python-fixedint, python-httplib2,
    python-httpretty, python-javaproperties, python-jsondiff, python-knack, python-marshmallow, python-
    opencensus, python-opencensus-context, python-opencensus-ext-threading, python-opentelemetry-api, python-
    opentelemetry-sdk, python-opentelemetry-semantic-conventions, python-opentelemetry-test-utils, python-
    pycomposefile, python-pydash, python-redis, python-retrying, python-semver, python-sshtunnel, python-
    strictyaml, python-sure, python-vcrpy, python-xmltodict contains the following fixes:

    Changes in python-argcomplete
    - Update to 3.3.0 (bsc#1222880):
      * Preserve compatibility with argparse option tuples of length 4.
        This update is required to use argcomplete on Python 3.11.9+ or
        3.12.3+.
    - update to 3.2.3:
      * Allow register-python-argcomplete output to be used as lazy-loaded
        zsh completion module (#475)
        - Move debug_stream initialization to helper method to allow fd 9
          behavior to be overridden in subclasses (#471)

    - update to 3.2.2:
      * Expand tilde in zsh

    - Remove coverage check
    - Fix zsh test failures: avoid coloring terminal

    - update to 3.2.1:
      *  Allow explicit zsh global completion activation (#467)
      *  Fix and test global completion in zsh (#463, #466)
      *  Add yes option to activate-global-python-argcomplete (#461)
      *  Test suite improvements
    - drop without_zsh.patch: obsolete

    - update to 3.1.6:
      *  Respect user choice in activate-global-python-argcomplete
      *  Escape colon in zsh completions. Fixes #456
      *  Call \_default as a fallback in zsh global completion

    - update to 3.1.4:
      * Call \_default as a fallback in zsh global completion
      * zsh: Allow to use external script (#453)
      * Add support for Python 3.12 and drop EOL 3.6 and 3.7 (#449)
      * Use homebrew prefix by default
      * zsh: Allow to use external script (#453)


    Changes in python-Fabric:
    - Update to 3.2.2
    - add fix-test-deps.patch to remove vendored dependencies
     *[Bug]: fabric.runners.Remote failed to properly deregister its SIGWINCH signal
        handler on shutdown; in rare situations this could cause tracebacks when
        the Python process receives SIGWINCH while no remote session is active.
        This has been fixed.
     * [Bug] #2204: The signal handling functionality added in Fabric 2.6 caused
        unrecoverable tracebacks when invoked from inside a thread (such as
        the use of fabric.group.ThreadingGroup) under certain interpreter versions.
        This has been fixed by simply refusing to register signal handlers when not
        in the main thread. Thanks to Francesco Giordano and others for the reports.
     * [Bug]: Neglected to actually add deprecated to our runtime dependency
        specification (it was still in our development dependencies). This has been fixed.
     * [Feature]: Enhanced fabric.testing in ways large and small:
        Backwards-compatibly merged the functionality of MockSFTP into MockRemote (may be
        opted-into by instantiating the latter with enable_sftp=True) so you can mock
        out both SSH and SFTP functionality in the same test, which was previously impossible.
        It also means you can use this in a Pytest autouse fixture to prevent any tests
        from accidentally hitting the network!
        A new pytest fixture, remote_with_sftp, has been added which leverages the previous
        bullet point (an all-in-one fixture suitable for, eg, preventing any incidental
        ssh/sftp attempts during test execution).
        A pile of documentation and test enhancements (yes, testing our testing helpers is a thing).
     * [Support]: Added a new runtime dependency on the Deprecated library.
     * [Support]: Language update: applied s/sanity/safety/g to the codebase
        (with the few actual API members using the term now marked deprecated & new ones added
        in the meantime, mostly in fabric.testing).
     * [Feature]: Add a new CLI flag to fab, fab --list-agent-keys, which will attempt
        to connect to your local SSH agent and print a key list, similarly to ssh-add -l.
        This is mostly useful for expectations-checking Fabric and Paramikos agent
        functionality, or for situations where you might not have ssh-add handy.
     * [Feature]: Implement opt-in support for Paramiko 3.2s AuthStrategy machinery, as follows:
        Added a new module and class, fabric.auth.OpenSSHAuthStrategy, which leverages
        aforementioned new Paramiko functionality to marry loaded SSH config files with
        Fabric-level and runtime-level parameters, arriving at what should
        be OpenSSH-client-compatible authentication behavior. See its API docs for details.
        Added new configuration settings:
          authentication.strategy_class, which defaults to None,
            but can be set to OpenSSHAuthStrategy to opt-in to the new behavior.
          authentication.identities, which defaults to the empty list, and can
            be a list of private key paths for use by the new strategy class.
     * [Bug] #2263: Explicitly add our dependency on decorator to setup.py instead of using
        Invokes old, now removed, vendored copy of same. This allows Fabric to happily use
        Invoke 2.1 and above

    - Update to 3.0.1
      * [Bug] #2241: A typo prevented Fabrics command runner from properly
        calling its superclass stop() method, which in tandem with a related
        Invoke bug meant messy or long shutdowns in many scenarios.
    - Changes from 3.0.0
      * [Feature]: Change the default configuration value for inline_ssh_env
        from False to True, to better align with the practicalities of common
        SSH server configurations.
        - Warning
          This change is backwards incompatible if you were using
          environment-variable-setting kwargs or config settings,
          such as Connection.run(command, env={'SOME': 'ENV VARS'}),
          and were not already explicitly specifying the value of inline_ssh_env.
      * [Bug] #1981: (fixed in #2195) Automatically close any open SFTP session
        during fabric.connection.Connection.close; this avoids issues encountered
        upon re-opening a previously-closed connection object.
      * [Support]: Drop support for Python <3.6, including Python 2.
        - Warning
          This is a backwards incompatible change if you are not yet on
          Python 3.6 or above; however, pip shouldnt offer you this
          version of Fabric as long as your pip version understands
          python_requires metadata.
    - Drop remove-mock.patch because now in upstream.
    - Drop remove-pathlib2.patch because now in upstream.

    - Add %{?sle15_python_module_pythons}

    - Remove conditional definition of python_module.

    - Add patch remove-pathlib2.patch:
      * Drop install_requires on pathlib2.

    - Update to 2.7.1:
      * [Bug] #1924: (also #2007) Overhaul behavior and testing re: merging together
        different sources for the key_filename parameter in
        Connection.connect_kwargs. This fixes a number of type-related errors
        (string objects have no extend attribute, cannot add lists to strings, etc).

    - Update to 2.7.0:
      * Add ~fabric.connection.Connection.shell, a belated port of the v1
        open_shell() feature.
      * Forward local terminal resizes to the remote end, when applicable.
        (For the technical: this means we now turn SIGWINCH into SSH
        window-change messages.)
      * Update ~fabric.connection.Connection temporarily so that it doesn't
        incidentally apply replace_env=True to local shell commands, only
        remote ones.
    - Add patch remove-mock.patch:
      * Use unittest.mock, instead of mock

    - pytest-relaxed now supports pytest 6, so test on all python versions.

    - Don't test on python310 -- gh#bitprophet/pytest-relaxed#12
      (This is mainly required by azure-cli in the primary python3
      flavor)

    - Update to 2.6.0:
      * [Feature] #1999: Add sudo support to Group. Thanks to Bonnie Hardin for
        the report and to Winston Nolan for an early patchset.
      * [Feature] #1810: Add put/get support to Group.
      * [Feature] #1868: Ported a feature from v1: interpolating the local path
        argument in Transfer.get with connection and remote filepath attributes.
        For example, cxn.get(remote='/var/log/foo.log', local='{host}/') is now
        feasible for storing a file in per-host-named directories or files, and
        in fact Group.get does this by default.
      * [Feature]: When the local path argument to Transfer.get contains nonexistent
        directories, they are now created instead of raising an error.
        Warning: This change introduces a new runtime dependency: pathlib2.
      * [Bug]: Fix a handful of issues in the handling and mocking of SFTP local paths
        and os.path members within fabric.testing; this should remove some occasional
        useless Mocks as well as hewing closer to the real behavior of things like
        os.path.abspath re: path normalization.
    - Update Requires from setup.py

    Changes in python-PyGithub:
    - Switch package to modern Python Stack on SLE-15
      + Add %{?sle15_python_module_pythons}
      + Drop %{?!python_module:%define python_module() python-%{**} python3-%{**}}
      + Drop %define skip_python2 1

    - Update to 1.57
      Breaking Changes
      * Add support for Python 3.11, drop support for Python 3.6 (#2332) (1e2f10d)
      Bug Fixes & Improvements
      * Speed up get requested reviewers and teams for pr (#2349) (6725ece)
      * [WorkflowRun] - Add missing attributes (run_started_at & run_attempt), remove deprecated unicode type
    (#2273) (3a6235b)
      * Add support for repository autolink references (#2016) (0fadd6b)
      * Add retry and pool_size to typing (#2151) (784a3ef)
      * Fix/types for repo topic team (#2341) (db9337a)
      * Add class Artifact (#2313) (#2319) (437ff84)

    - Update to 1.56
       This is the last release that will support Python 3.6.
      *Bug Fixes & Improvements
       Create repo from template (#2090) (b50283a)
       Improve signature of Repository.create_repo (#2118) (001970d)
       Add support for 'visibility' attribute preview for Repositories (#1872) (8d1397a)
       Add Repository.rename_branch method (#2089) (6452ddf)
       Add function to delete pending reviews on a pull request (#1897) (c8a945b)
       Cover all code paths in search_commits (#2087) (f1faf94)
       Correctly deal when PaginatedList's data is a dict (#2084) (93b92cd)
       Add two_factor_authentication in AuthenticatedUser. (#1972) (4f00cbf)
       Add ProjectCard.edit() to the type stub (#2080) (d417e4c)
       Add method to delete Workflow runs (#2078) (b1c8eec)
       Implement organization.cancel_invitation() (#2072) (53fb498)
       Feat: Add html_url property in Team Class. (#1983) (6570892)
       Add support for Python 3.10 (#2073) (aa694f8)
       Add github actions secrets to org (#2006) (bc5e595)
       Correct replay for Organization.create_project() test (#2075) (fcc1236)
       Fix install command example (#2043) (99e00a2)
       Fix: #1671 Convert Python Bool to API Parameter for Authenticated User Notifications (#2001) (1da600a)
       Do not transform requestHeaders when logging (#1965) (1265747)
       Add type to OrderedDict (#1954) (ed7d0fe)
       Add Commit.get_pulls() to pyi (#1958) (b466470)
       Adding headers in GithubException is a breaking change (#1931) (d1644e3)

    - Update to 1.55:
      * Remove client_id/client_secret authentication (#1888) (901af8c8)
      * Adjust to Github API changes regarding emails (#1890) (2c77cfad)
        + This impacts what AuthenticatedUser.get_emails() returns
      * Export headers in GithubException (#1887) (ddd437a7)
      * Do not import from unpackaged paths in typing (#1926) (27ba7838)
      * Implement hash for CompletableGithubObject (#1922) (4faff23c)
      * Use right variable in both get_check_runs() (#1889) (3003e065)
      * fix bad assertions in github.Project.edit (#1817) (6bae9e5c)
      * Add support for deleting repository secrets (#1868) (696793de)
      * Adding github actions secrets (#1681) (c90c050e)
      * Drop support for Python 3.5 (#1770) (63e4fae9)
      * Fix stubs file for Repository (fab682a5)
      * The Github.get_installation(integer) method has been removed.
      * Repository.create_deployment()'s payload parameter is now a dictionary.
      * Add support for Check Suites (#1764) (6d501b28)
      * Add missing preview features of Deployment and Deployment Statuses API
      * Add Support for Check Runs (#1727) (c77c0676)
      * Add WorkflowRun.workflow_id (#1737) (78a29a7c)
      * Added support for the Self-Hosted actions runners API (#1684) (24251f4b)
      * Fix Branch protection status in the examples (#1729) (88800844)
      * Filter the DeprecationWarning in Team tests (#1728) (23f47539)
      * Added get_installations() to Organizations (#1695) (b42fb244)
      * Fix #1507: Add new Teams: Add or update team repository endpoint
      * Added support for `Repository.get_workflow_runs` parameters
      * feat(pullrequest): add the rebaseable attribute (#1690) (ee4c7a7e)
      * Add support for deleting reactions (#1708) (f7d203c0)
      * Add get_timeline() to Issue's type stubs (#1663) (6bc9ecc8)

    - Update to 1.53:
      * Add method get_team_membership for user to Team  (#1658) (749e8d35)
      * PaginatedList's totalCount is 0 if no last page (#1641) (69b37b4a)
      * Add initial support for Github Apps. (#1631) (260558c1)
      * Add delete_branch_on_merge arg to Repository.edit type stub
        (#1639) (15b5ae0c)
      * upload_asset with data in memory (#1601) (a7786393)
      * Make Issue.closed_by nullable (#1629) (06dae387)
      * Add support for workflow dispatch event (#1625) (16850ef1)
      * Do not check reaction_type before sending (#1592) (136a3e80)
      * more flexible header splitting (#1616) (85e71361)
      * Add support for deployment statuses (#1588) (048c8a1d)
      * Adds the 'twitter_username' attribute to NamedUser. (#1585) (079f75a7)
      * Add support for Workflow Runs (#1583) (4fb1d23f)
      * Small documentation correction in Repository.py (#1565) (f0f6ec83)
      * Remove 'api_preview' parameter from type stubs and docstrings
        (#1559) (cc1b884c)
      * Repository.update_file() content also accepts bytes (#1543) (9fb8588b)
      * Fix Repository.get_issues stub (#1540) (b40b75f8)
      * Check all arguments of NamedUser.get_repos() (#1532) (69bfc325)
      * Remove RateLimit.rate (#1529) (7abf6004)
      * PullRequestReview is not a completable object (#1528) (19fc43ab)
      * Remove pointless setters in GitReleaseAsset (#1527) (1dd1cf9c)
      * Drop some unimplemented methods in GitRef (#1525) (d4b61311)
      * Fixed formatting of docstrings for
        `Repository.create_git_tag_and_release()`
        and `StatsPunchCard`. (#1520) (ce400bc7)
      * Remove Repository.topics (#1505) (53d58d2b)
      * Correct Repository.get_workflows() (#1518) (8727003f)
      * correct Repository.stargazers_count return type to int (#1513) (b5737d41)
      * Raise a FutureWarning on use of client_{id,secret} (#1506) (2475fa66)
      * Improve type signature for create_from_raw_data (#1503) (c7b5eff0)
      * feat(column): move, edit and delete project columns (#1497) (a32a8965)
      * Add support for Workflows (#1496) (a1ed7c0e)
      * Add OAuth support for GitHub applications (4b437110)
      * Create AccessToken entity (4a6468aa)
      * Extend installation attributes (61808da1)

    - Update to 1.51
      + New features
        * PyGithub now supports type checking
        * Ability to retrieve public events
        * Add and handle the maintainer_can_modify attribute in PullRequest
        * List matching references
        * Add create_repository_dispatch
        * Add some Organization and Repository attributes.
        * Add create project method
      + Bug Fixes & Improvements
        * Drop use of shadow-cat for draft PRs
        * AuthenticatedUser.get_organization_membership() should be str
        * Drop documentation for len() of PaginatedList
        * Fix param name of projectcard's move function
        * Correct typos found with codespell
        * Export IncompletableObject in the github namespace
        * Add GitHub Action workflow for checks
        * Drop unneeded ignore rule for flake8
        * Use pytest to parametrize tests
        * Type stubs are now packaged with the build
        * Get the project column by id
    - Drop parametrized and pytest-cov from BuildRequires.

    - Update to 1.47
      + Bug Fixes & Improvements
        * Add support to edit and delete a project (#1434) (f11f739)
        * Add method for fetching pull requests associated with a commit (#1433) (0c55381)
        * Add 'get_repo_permission' to Team class (#1416) (219bde5)
        * Add list projects support, update tests (#1431) (e44d11d)
        * Don't transform completely in PullRequest.*assignees (#1428) (b1c3549)
        * Add create_project support, add tests (#1429) (bf62f75)
        * Add draft attribute, update test (bd28524)
        * Docstring for Repository.create_git_tag_and_release (#1425) (bfeacde)
        * Create a tox docs environment (#1426) (b30c09a)
        * Add Deployments API (#1424) (3d93ee1)
        * Add support for editing project cards (#1418) (425280c)
        * Add draft flag parameter, update tests (bd0211e)
        * Switch to using pytest (#1423) (c822dd1)
        * Fix GitMembership with a hammer (#1420) (f2939eb)
        * Add support to reply to a Pull request comment (#1374) (1c82573)
        * PullRequest.update_branch(): allow expected_head_sha to be empty (#1412) (806130e)
        * Implement ProjectCard.delete() (#1417) (aeb27b7)
        * Add pre-commit plugin for black/isort/flake8 (#1398) (08b1c47)
        * Add tox (#1388) (125536f)
        * Open file in text mode in scripts/add_attribute.py (#1396) (0396a49)
        * Silence most ResourceWarnings (#1393) (dd31a70)
        * Assert more attributes in Membership (#1391) (d6dee01)
        * Assert on changed Repository attributes (#1390) (6e3ceb1)
        * Add reset to the repr for Rate (#1389) (0829af8)

    - Update to 1.46
      + Bug Fixes & Improvements
        * Add repo edit support for delete_branch_on_merge
        * Fix mistake in Repository.create_fork()
        * Correct two attributes in Invitation
        * Search repo issues by string label
        * Correct Repository.create_git_tag_and_release()
        * exposed seats and filled_seats for Github Organization Plan
        * Repository.create_project() body is optional
        * Implement move action for ProjectCard
        * Tidy up ProjectCard.get_content()
        * Added nested teams and parent
        * Correct parameter for Label.edit
        * doc: example of Pull Request creation
        * Fix PyPI wheel deployment
    - No longer build Python 2 package
    - Drop BuildRequires on mock, no longer required
    - Drop no-hardcoded-dep.patch, no longer required

    - Update to 1.45:
      + Breaking Changes
        * Branch.edit_{user,team}_push_restrictions() have been removed
          The new API is:
             Branch.add_{user,team}_push_restrictions() to add new members
             Branch.replace_{user,team}_push_restrictions() to replace all members
             Branch.remove_{user,team}_push_restrictions() to remove members
        * The api_preview parameter to Github() has been removed.
      + Bug Fixes & Improvements
        * Allow sha=None for InputGitTreeElement
        * Support github timeline events.
        * Add support for update branch
        * Refactor Logging tests
        * Fix rtd build
        * Apply black to whole codebase
        * Fix class used returning pull request comments
        * Support for create_fork
        * Use Repository.get_contents() in tests
        * Allow GithubObject.update() to be passed headers
        * Correct URL for assignees on PRs
        * Use inclusive ordered comparison for 'parameterized' requirement
        * Deprecate Repository.get_dir_contents()
        * Apply some polish to manage.sh
    - Refresh no-hardcoded-dep.patch

    - Add patch to not pull in hardcoded dependencies:
      * no-hardcoded-dep.patch

    - Update to 1.44.1:
      * Too many changes to enumerate.
    - Drop PyGithub-drop-network-tests.patch, the test in question no longer
      requires network access.
    - Drop fix-httpretty-dep.patch, the httpretty requirement has been relaxed
      upstream.
    - Use %python_expand to run the test suite, it works fine on Python 3 now.
    - Add mock and parameterized to BuildRequires, the test suite requires them.

    - Update to 1.43.8:
      * Add two factor attributes on organizations (#1132) (a073168)
      * Add Repository methods for pending invitations (#1159) (57af1e0)
      * Adds get_issue_events to PullRequest object (#1154) (acd515a)
      * Add invitee and inviter to Invitation (#1156) (0f2beac)
      * Adding support for pending team invitations (#993) (edab176)
      * Add support for custom base_url in GithubIntegration class (#1093) (6cd0d64)
      * GithubIntegration: enable getting installation (#1135) (1818704)
      * Add sorting capability to Organization.get_repos() (#1139) (ef6f009)
      * Add new Organization.get_team_by_slug method (#1144) (4349bca)
      * Add description field when creating a new team (#1125) (4a37860)
      * Handle a path of / in Repository.get_contents() (#1070) (102c820)
      * Add issue lock/unlock (#1107) (ec7bbcf)
      * Fix bug in recursive repository contents example (#1166) (8b6b450)
      * Allow name to be specified for upload_asset (#1151) (8d2a6b5)
      * Fixes #1106 for GitHub Enterprise API (#1110) (5406579)

    - Update to 1.43.7:
      * Exclude tests from PyPI distribution (#1031) (78d283b9)
      * Add codecov badge (#1090) (4c0b54c0)
    - Update to 1.43.6:
      * New features
        o Add support for Python 3.7 (#1028) (6faa00ac)
        o Adding HTTP retry functionality via urllib3 (#1002) (5ae7af55)
        o Add new dismiss() method on PullRequestReview (#1053) (8ef71b1b)
        o Add since and before to get_notifications (#1074) (7ee6c417)
        o Add url parameter to include anonymous contributors in get_contributors (#1075) (293846be)
        o Provide option to extend expiration of jwt token (#1068) (86a9d8e9)
      * Bug Fixes & Improvements
        o Fix the default parameter for PullRequest.create_review (#1058) (118def30)
        o Fix get_access_token (#1042) (6a89eb64)
        o Fix Organization.add_to_members role passing (#1039) (480f91cf)
      * Deprecation
        o Remove Status API (6efd6318)
    - Add patch fix-httpretty-dep.patch
    Changes in python-antlr4-python3-runtime:
    - Switch package to modern Python Stack on SLE-15
      + Add %{?sle15_python_module_pythons}
      + Drop %{?!python_module:%define python_module() python-%{**} python3-%{**}}
      + Drop %define skip_python2 1
      + Drop support for older Python 3.x versions

    - fix build for python 3.12

    - require setuptools

    - Update to version 4.13.1
      csharp target
      * [CSharp] Fix for #4386 -- change signatures for ReportAttemptingFullContext()
        and ReportContextSensitivity() to be identical to all other targets (target:csharp,
        type:cleanup)
      go target
      * Move GetText(), SetText(), and String() from CommonToken to BaseToken
        (target:go, type:cleanup)
      * Restore 'Obtained from string' source name. (target:go, type:cleanup)
      * fix: Fix very minor code issues spotted by goreportcard.com (target:go, type:cleanup)
      java target
      * Java: suppress this-escape warning introduced in JDK 21. (actions, target:java)
      javascript target
      * Adds default targets for babel configuration (target:javascript)
      * fix dependabot warnings (target:javascript, type:cleanup)
      swift target
      * [SWIFT] Add Antlr4Dynamic product (target:swift)
      * Cleanup duplicate SwiftTarget code (target:swift, type:cleanup)
      dart target
      * [Dart] Fix for #4320--export additional types (type:bug, target:dart)
    - from version 4.13.0
      Issues fixed
      * antlr4 jar doubled in size in 4.9.3 (unicode, comp:performance)
      * Go: exponentially bad/absymal performance as of ... (type:bug, target:go)
      * Go runtime panic (type:bug, target:go)
      Improvements, features
      * Update LexerATNSimulator.cs with virtual Consume (type:improvement, target:csharp)
      * Feature/fixembedding (type:improvement, target:go, comp:performance)
      * Provide Javascript port of TokenStreamRewriter (type:feature,
        target:javascript, target:typescript)
    - from version 4.12.0
      Issues fixed
      * github actions now fail for python2 and ubuntu clang and ubuntu swift
        (comp:runtime, comp:build, comp:testing)
      * js mergeArrays output differs from java (atn-analysis, target:javascript)
      * C++ target fails Performance/DropLoopEntryBranchInLRRule_4.txt
        (atn-analysis, type:bug, target:cpp)
      * Wrong grammarFileName in generated code (code-gen, type:bug)
      * C++ crashes on new test ParserExec/ListLabelsOnRuleRefStartOfAlt.txt
        (atn-analysis, type:bug, target:cpp)
      * [JavaScript runtime] Bad field name, bad comments (type:bug)
      Improvements, features
      * Fully qualify std::move invocations to fix -Wunqualified-std-cast-call
        (type:improvement, target:cpp)
      * Extract FileUtils updates by @ericvergnaud (type:improvement,
        cross-platform-issue, comp:testing)
      * Extract unit test updates by @ericvergnaud needed for TypeScript
        (type:improvement, comp:testing)
      * [Go target] Fix for #3926: Add accessors for tree navigation to interfaces
        in generated parser (trees-contexts, code-gen, type:improvement, target:go)
      * GitHub Workflows security hardening (actions, type:improvement, comp:testing)
    - from version 4.11.1
      * Just fixes 4.11.0 release issue. I forgot to change runtime
        tool version so it didn't say SNAPSHOT.
    - from version 4.11.0
      Issues fixed
      * Disable failing CI tests in master (comp:build, comp:testing)
      * Create accessor for Go-based IntervalSet.intervals (target:go)
      * Grammar Name Conflict Golang with SPARQL issue (target:go, type:cleanup)
      * Dependency declaration error in ANTLR 4.10.1 (comp:build)
      * Drop old version of Visual Studio C++ (2013, 2015, 2017)
        (comp:build, target:cpp)
      * Circular grammar inclusion causes stack overflow in the tool.
        (comp:tool, type:bug)
      * Cpp, Go, JavaScript, Python2/3: Template rendering error. (code-gen, comp:runtime,
        target:java, target:javascript, target:python2, target:python3, target:go)
      Improvements, features
      * Augment error message during testing to include full cause of problem.
        (type:improvement, comp:testing)
      * Include swift & tool verification in CI workflow (type:improvement,
        comp:build, cross-platform-issue, target:swift)
      * Issue #3783: CI Check Builds (type:improvement, comp:build,
        cross-platform-issue, comp:testing)
      * Parallel lock free testing, remove potential deadlocks, cache static data,
        go to descriptor via test (comp:runtime, type:improvement, comp:testing)
      * update getting-started doc (type:improvement, comp:doc)
      * Getting Started has error (type:improvement, comp:doc)
      * new nuget directory for building ANTLR4 C++ runtime as 3 Nuget packages
        (type:improvement, comp:build, target:cpp)
      * Add interp tool like TestRig (comp:tool, type:feature)
      * Issue 3720: Java 2 Security issue (type:improvement, target:java)
      * Cpp: Disable warnings for external project (type:bug, type:improvement, target:cpp)
      * Fix Docker README for arm OS user (type:improvement, comp:doc)
    - from version 4.10.1
      * [C++] Remove reference to antlrcpp:s2ws
      * Update publishing instruction for Dart
    - from version 4.10.0
      Issues fixed
      * C++ runtime: Version identifier macro ? (target:cpp, type:cleanup)
      * Generating XPath lexer/parser (actions, type:bug)
      * do we need this C++ ATN serialization? (target:cpp, type:cleanup)
      * Incorrect type of token with number 0xFFFF because of incorrect
        ATN serialization (atn-analysis, type:bug)
      * Clean up ATN serialization: rm UUID and shifting by value of 2
        (atn-analysis, type:cleanup)
      * The parseFile method of the InterpreterDataReader class is missing
        code: 'line = br.readLine();' (type:bug, target:java)
      * antlr.runtime.standard 4.9.3 invalid strong name.
        (type:bug, comp:build, target:csharp)
      * Serialized ATN data element 810567 element 11 out of
        range 0..65535 (atn-analysis, type:cleanup)
      * Go target, unable to check when custom error strategy
        is in recovery mode (target:go)
      * Escape issue for characeters (grammars, type:bug)
      * antlr4 java.lang.NullPointerException Antlr 4 4.8
        (grammars, comp:tool, type:bug)
      * UnsupportedOperationException while generating code for large grammars.
        (atn-analysis, type:cleanup)
      * Add a more understandable message than 'Serialized ATN data element ....
        element ... out of range 0..65535' (atn-analysis, type:cleanup)
      * avoid java.lang.StackOverflowError (lexers, error-handling)
      * Getting this error: Exception in thread 'main' java.lang.UnsupportedOperationException:
        Serialized ATN data element out of range (atn-analysis, type:cleanup)
      Improvements, features
      * Updated getting started with Cpp documentation. (type:improvement, comp:doc)
      * Escape bad words during grammar generation (code-gen, type:improvement)
      * Implement caseInsensitive option (lexers, options, type:improvement)
      * Some tool bugfixes (error-handling, comp:tool, type:improvement, type:cleanup)
    - Run testsuite using the tests/run.py script instead of %pyunittest
    - Switch build systemd from setuptools to pyproject.toml
    - Update BuildRequires from pyproject.toml
    - Update filename pattern in %files section

    - Update to version 4.9.3
      Issues fixed
      * Swift Target Crashes with Multi-Threading
      * JavaScript Runtime bug
      * Go target, cannot use superClass for the lexer grammar!
      * Python runtime is inconsistent with Java
      * FunctionDef source extract using getText()
      * Provide .NET Framework target in the csharp nuget package
      * Go target for Antlr tool, type ',int8' => 'int8'
      * Flutter/Dart web support
      * Allow Antlr Javascript runtime to be loaded into Kindle Touch
      * Fix Go test suite
      * Weird error
      Improvements, features
      * [C++] Use faster alternative to dynamic_cast when not testing inherit
      * Stackoverflow after upgrading from 4.6 to 4.7
    - from version 4.9.2
      Issues fixed
      * CSharp and Java produce different results for identical input, identical tokens
      Improvements, features
      * Moved away from travis-ci.com
    - Source upstream tarball from Github since PyPi tarball no longer ships testsuite

    - Update to version 4.9.1.
      * Improve python3 performance by adding slots
      * Fix incorrect python token string templates
    - Add testing.
    - Skip python2 because this is for python3.
    - Use python_alternative
    Changes in python-avro:
    - Switch package to modern Python Stack on SLE-15
      + Add %{?sle15_python_module_pythons}
      + Drop %define skip_python2 1
    - Update to version 1.11.3:
      + See jira board for all the fixes addressed in this release:
        https://issues.apache.org/jira/browse/AVRO-3855?jql=project%3DAVRO%20AND%20fixVersion%3D1.11.3
    - Drop py311.patch: fixed upstream.

    - Add py311.patch to make tests compatible with python 3.11 gh#apache/avro#1961

    - Update to 1.11.1 (from GitHub release notes):
      - Avro specification
        - Clarify which names are allowed to be qualified with
          namespaces
        - Inconsistent behaviour on types as invalid names
        - Clarify how fullnames are created, with example
        - IDL: add syntax to create optional fields
        - Improve docs for logical type annotation
      - Python
        - Scale assignment optimization
        - 'Scale' property from decimal object
        - Byte reading in avro.io does not assert bytes read
        - validate the default value of an enum field
        - Pass LogicalType to BytesDecimalSchema
      - Website
        - Website refactor
        - Document IDL support in IDEs
    Changes in python-chardet:
    - update to 5.2.0:
      * Adds support for running chardet CLI via `python -m chardet`

    Changes in python-distro:
    - Switch to autosetup macro.

    - update to 1.9.0:
      * Refactor distro.info() method to return an InfoDict [#360]
      * Ignore the file '/etc/board-release' [#353]
      * Ignore the file '/etc/ec2_version' [#359]
      * Test on modern versions of CPython and PyPy and macOS [#362]
      * Add support for ALT Linux Server 10.1 distribution [#354]
      * Add Debian Testing to the tests [#356]
      * Update archlinux resource for tests [#352]

    - Remove duplicate files calling %fdupes

    - add sle15_python_module_pythons

    - update to 1.8.0:
      * Lowered `LinuxDistribution._distro_release_info` method complexity
        [#327]
      * Added official support for Buildroot distribution [#329]
      * Added official support for Guix distribution [#330]
      * Added support for `/etc/debian_version` [#333] & [#349]
      * Fixed a typography in CONTRIBUTING.md [#340]
      * Improved README.md 'Usage' code block [#343]
      * Bumped black to v22.3.0 in pre-commit.ci configuration [#331]
      * Enabled GitHub Dependabot to keep GitHub Actions up to date [#335]

    - remove shebang from distro.py
    - update to version 1.7.0:
     - BACKWARD COMPATIBILITY:
     - Dropped support for EOL Pythons 2.7, 3.4 and 3.5 [[#281](https://github.com/python-
    distro/distro/pull/281)]
     - Dropped support for LSB and `uname` back-ends when `--root-dir` is specified
    [[#311](https://github.com/python-distro/distro/pull/311)]
     - Moved `distro.py` to `src/distro/distro.py` [[#315](https://github.com/python-distro/distro/pull/315)]
     - ENHANCEMENTS:
     - Documented that `distro.version()` can return an empty string on rolling releases
    [[#312](https://github.com/python-distro/distro/pull/312)]
     - Documented support for Python 3.10 [[#316](https://github.com/python-distro/distro/pull/316)]
     - Added official support for Rocky Linux distribution [[#318](https://github.com/python-
    distro/distro/pull/318)]
     - Added a shebang to `distro.py` to allow standalone execution [[#313](https://github.com/python-
    distro/distro/pull/313)]
     - Added support for AIX platforms [[#311](https://github.com/python-distro/distro/pull/311)]
     - Added compliance for PEP-561 [[#315](https://github.com/python-distro/distro/pull/315)]
     - BUG FIXES:
     - Fixed `include_uname` parameter oversight [[#305](https://github.com/python-distro/distro/pull/305)]
     - Fixed crash when `uname -rs` output is empty [[#304](https://github.com/python-distro/distro/pull/304)]
     - Fixed Amazon Linux identifier in `distro.id()` documentation [[#318](https://github.com/python-
    distro/distro/pull/318)]
     - Fixed OpenSuse >= 15 support [[#319](https://github.com/python-distro/distro/pull/319)]
     - Fixed encoding issues when opening distro release files [[#324](https://github.com/python-
    distro/distro/pull/324)]
     - Fixed `linux_distribution` regression introduced in [[#230](https://github.com/python-
    distro/distro/pull/230)] [[#325](https://github.com/python-distro/distro/pull/325)]

    - Tests: Set locale to UTF-8 to fix tests on Leap 15.3.

    - Expliciting setting of locale is not necessary anymore
      (gh#python-distro/distro#223).

    - Update to version 1.6.0
      * Deprecated the distro.linux_distribution() function. Use distro.id(), distro.version() and
    distro.name() instead [#296]
      * Deprecated Python 2.7, 3.4 and 3.5 support. Further releases will only support Python 3.6+
      * Added type hints to distro module [#269]
      * Added __version__ for checking distro version [#292]
      * Added support for arbitrary rootfs via the root_dir parameter [#247]
      * Added the --root-dir option to CLI [#161]
      * Added fallback to /usr/lib/os-release when /etc/os-release isn't available [#262]
      * Fixed subprocess.CalledProcessError when running lsb_release [#261]
      * Ignore /etc/iredmail-release file while parsing distribution [#268]
      * Use a binary file for /dev/null to avoid TextIOWrapper overhead [#271]

    - use %pytest macro

    - Enable tests properly (this is pytest, not unittest),
    Changes in python-docker:
    - update to 7.0.0:
      * Removed SSL version (`ssl_version`) and explicit hostname
        check (`assert_hostname`) options (#3185)
      * Python 3.7+ supports TLSv1.3 by default
      * Websocket support is no longer included by default (#3123)
      * Use `pip install docker[websockets]` to include `websocket-
        client` dependency
      * By default, `docker-py` hijacks the TCP connection and does
        not use Websockets
      * Websocket client is only required to use
        `attach_socket(container, ws=True)`
      * Python 3.7 no longer supported (reached end-of-life June
        2023) (#3187)
      * Python 3.12 support (#3185)
      * Full `networking_config` support for `containers.create()`
      * Replaces `network_driver_opt` (added in 6.1.0)
      * Add `health()` property to container that returns status
        (e.g. `unhealthy`)
      * Add `pause` option to `container.commit()` (#3159)
      * Add support for bind mount propagation (e.g. `rshared`,
        `private`)
      * Add support for `filters`, `keep_storage`, and `all` in
        `prune_builds()` on API v1.39+ (#3192)
      * Consistently return `docker.errors.NotFound` on 404 responses
      * Validate tag format before push (#3191)

    - update to 6.1.3:
      * Bugfixes
        - Fix eventlet compatibility (#3132)
    - update to 6.1.2:
      * Bugfixes
        - Fix for socket timeouts on long docker exec calls (#3125)
        - Respect timeout param on Windows (#3112)
    - update to 6.1.1:
      * Upgrade Notes (6.1.x)
        - Errors are no longer returned during client initialization if
          the credential helper cannot be found. A warning will be
          emitted instead, and an error is returned if the credential
          helper is used.
      * Bugfixes
        - Fix containers.stats() hanging with stream=True
        - Correct return type in docs for containers.diff() method
    - update to 6.1.0:
      * Upgrade Notes
        - Errors are no longer returned during client initialization if
          the credential helper cannot be found. A warning will be
          emitted instead, and an error is returned if the credential
          helper is used.
      * Features
        - Python 3.11 support
        - Use poll() instead of select() on non-Windows platforms
        - New API fields
          - network_driver_opt on container run / create
          - one-shot on container stats
          - status on services list
      * Bugfixes
        - Support for requests 2.29.0+ and urllib3 2.x
        - Do not strip characters from volume names
        - Fix connection leak on container.exec_* operations
        - Fix errors closing named pipes on Windows
    - update to 6.0.1:
      * Notice
        This version is not compatible with requests 2.29+ or urllib3
        2.x.
        Either add requests < 2.29 and urllib3 < 2 to your requirements
        or upgrade to to the latest docker-py release.
      * Bugfixes
        - Fix for The pipe has been ended errors on Windows (#3056)
        - Support floats for timestamps in Docker logs (since / until)
          (#3031)
    - update to 6.0.0:
      * Upgrade Notes
        - Minimum supported Python version is 3.7+
        - When installing with pip, the docker[tls] extra is deprecated
          and a no-op, use docker for same functionality (TLS support
          is always available now)
        - Native Python SSH client (used by default /
          use_ssh_client=False) will now
        - reject unknown host keys with
          paramiko.ssh_exception.SSHException
        - Short IDs are now 12 characters instead of 10 characters
          (same as Docker CLI)
        - Version metadata is now exposed as __version__
      * Features
        - Python 3.10 support
        - Automatically negotiate most secure TLS version
        - Add platform (e.g. linux/amd64, darwin/arm64) to container
          create & run
        - Add support for GlobalJob and ReplicatedJobs for Swarm
        - Add remove() method on Image
        - Add force param to disable() on Plugin
      * Bugfixes
        - Fix install issues on Windows related to pywin32
        - Do not accept unknown SSH host keys in native Python SSH mode
        - Use 12 character short IDs for consistency with Docker CLI
        - Ignore trailing whitespace in .dockerignore files
        - Fix IPv6 host parsing when explicit port specified
        - Fix ProxyCommand option for SSH connections
        - Do not spawn extra subshell when launching external SSH
          client
        - Improve exception semantics to preserve context
        - Documentation improvements (formatting, examples, typos,
          missing params)
      * Miscellaneous
        - Upgrade dependencies in requirements.txt to latest versions
        - Remove extraneous transitive dependencies
        - Eliminate usages of deprecated functions/methods
        - Test suite reliability improvements
        - GitHub Actions workflows for linting, unit tests, integration
          tests, and publishing releases

    - add sle15_python_module_pythons

    - python-six is not required as well

    - python-mock actually not required for build

    - update to 5.0.3:
      * Add cap_add and cap_drop parameters to service create and ContainerSpec
      * Add templating parameter to config create
      * Bump urllib3 to 1.26.5
      * Bump requests to 2.26.0
      * Remove support for Python 2.7
      * Make Python 3.6 the minimum version supported

    - Update to 4.4.4
    From project changelog:
            4.4.4
                    Bugfixes
                            Remove LD_LIBRARY_PATH and SSL_CERT_FILE environment variables when shelling out
    to the ssh client
            4.4.3
                    Features
                            Add support for docker.types.Placement.MaxReplicas
                    Bugfixes
                            Fix SSH port parsing when shelling out to the ssh client
            4.4.2
                    Bugfixes
                            Fix SSH connection bug where the hostname was incorrectly trimmed and the error
    was hidden
                            Fix docs example
                    Miscellaneous
                            Add Python3.8 and 3.9 in setup.py classifier list
            4.4.1
                    Bugfixes
                            Avoid setting unsuported parameter for subprocess.Popen on Windows
                            Replace use of deprecated 'filter' argument on ''docker/api/image'

    - update to 4.4.0:
      - Add an alternative SSH connection to the paramiko one, based on shelling out to the SSh client.
    Similar to the behaviour of Docker cli
      - Default image tag to `latest` on `pull`
      - Fix plugin model upgrade
      - Fix examples URL in ulimits
      - Improve exception messages for server and client errors
      - Bump cryptography from 2.3 to 3.2
      - Set default API version to `auto`
      - Fix conversion to bytes for `float`
      - Support OpenSSH `identityfile` option
      - Add `DeviceRequest` type to expose host resources such as GPUs
      - Add support for `DriverOpts` in EndpointConfig
      - Disable compression by default when using container.get_archive method
      - Update default API version to v1.39
      - Update test engine version to 19.03.12

    - update to 4.2.2:
      - Fix context load for non-docker endpoints

    - update to 4.2.1:
      - Add option on when to use `tls` on Context constructor
      - Make context orchestrator field optional

    - Bump required version of pycreds to 0.4.0 (sync with requirements.txt)
    - update to 3.7.0 (mandatory for latest docker-compose)
    - add python-dockerpycreds dependency in the spec file
      rebase hide_py_pckgmgmt.patch
    Changes in python-fakeredis:

    - update to 2.21.0:
      * Implement all TOP-K commands (`TOPK.INFO`, `TOPK.LIST`,
        `TOPK.RESERVE`,
      * `TOPK.ADD`, `TOPK.COUNT`, `TOPK.QUERY`, `TOPK.INCRBY`) #278
      * Implement all cuckoo filter commands #276
      * Implement all Count-Min Sketch commands #277
      * Fix XREAD blocking bug #274 #275
      * EXAT option does not work #279

    - update to 2.20.1:
      * Fix `XREAD` bug #256
      * Testing for python 3.12

    - update to 2.20.0:
      * Implement `BITFIELD` command #247
      * Implement `COMMAND`, `COMMAND INFO`, `COMMAND COUNT` #248

    - Remove unnecessary BR on python-lupa

    - update to 2.19.0:
      * Implement Bloom filters commands #239
      * Fix error on blocking XREADGROUP #237

    - update to 2.18.1:
      * Fix stream type issue #233

    - update to 2.18.0:
      * Implement `PUBSUB NUMPAT` #195, `SSUBSCRIBE` #199, `SPUBLISH`
        #198, `SUNSUBSCRIBE` #200, `PUBSUB SHARDCHANNELS` #196, `PUBSUB
        SHARDNUMSUB` #197
      * Fix All aio.FakeRedis instances share the same server #218

    - update to 2.17.0:
      * Implement `LPOS` #207, `LMPOP` #184, and `BLMPOP` #183
      * Implement `ZMPOP` #191, `BZMPOP` #186
      * Fix incorrect error msg for group not found #210
      * fix: use same server_key within pipeline when issued watch
        issue with ZRANGE and ZRANGESTORE with BYLEX #214
      * Implemented support for `JSON.MSET` #174, `JSON.MERGE` #181
      * Add support for version for async FakeRedis #205
      * Updated how to test django_rq #204

    - update to 2.15.0:
      * Implemented support for various stream groups commands:
      * `XGROUP CREATE` #161, `XGROUP DESTROY` #164, `XGROUP SETID`
        #165, `XGROUP DELCONSUMER` #162,
      * `XGROUP CREATECONSUMER` #163, `XINFO GROUPS` #168, `XINFO
        CONSUMERS` #168, `XINFO STREAM` #169, `XREADGROUP` #171,
      * `XACK` #157, `XPENDING` #170, `XCLAIM` #159, `XAUTOCLAIM`
      * Implemented sorted set commands:
      * `ZRANDMEMBER` #192, `ZDIFF` #187, `ZINTER` #189, `ZUNION`
        #194, `ZDIFFSTORE` #188,
      * `ZINTERCARD` #190, `ZRANGESTORE` #193
      * Implemented list commands:
      * `BLMOVE` #182,
      * Improved documentation.
      * Fix documentation link
      * Fix requirement for packaging.Version #177
      * Implement `HRANDFIELD` #156
      * Implement `JSON.MSET`
      * Improve streams code

    - update to 2.13.0:
      * Fixed xadd timestamp (fixes #151) (#152)
      * Implement XDEL #153
      * Improve test code
      * Fix reported security issue
      * Add support for `Connection.read_response` arguments used in
        redis-py 4.5.5 and 5.0.0
      * Adding state for scan commands (#99)
      * Improved documentation (added async sample, etc.)

    - update to 2.12.0:
      * Implement `XREAD` #147
      * Unique FakeServer when no connection params are provided
      * Minor fixes supporting multiple connections
      * Update documentation
      * connection parameters awareness:
      * Creating multiple clients with the same connection parameters
        will result in the same server data structure.
      * Fix creating fakeredis.aioredis using url with user/password

    - add sle15_python_module_pythons

    - Update to 2.10.3:
      * Support for redis-py 5.0.0b1
      * Include tests in sdist (#133)
      * Fix import used in GenericCommandsMixin.randomkey (#135)
      * Fix async_timeout usage on py3.11 (#132)
      * Enable testing django-cache using FakeConnection.
      * All geo commands implemented
      * Fix bug for xrange
      * Fix bug for xrevrange
      * Implement XTRIM
      * Add support for MAXLEN, MAXID, LIMIT arguments for XADD command
      * Add support for ZRANGE arguments for ZRANGE command #127
      * Relax python version requirement #128
      * Support for redis-py 4.5.0 #125

    - update to 2.7.1:
      * Fix import error for NoneType (#120)
      * Implement
          - JSON.ARRINDEX
          - JSON.OBJLEN
          - JSON.OBJKEYS
          - JSON.ARRPOP
          - JSON.ARRTRIM
          - JSON.NUMINCRBY
          - JSON.NUMMULTBY
          - XADD
          - XLEN
          - XRANGE
          - XREVRANGE
      * Implement `JSON.TYPE`, `JSON.ARRLEN` and `JSON.ARRAPPEND`
      * Fix encoding of None (#118)

    - update to v2.5.0:
      * Implement support for BITPOS (bitmap command) (#112)
      * Fix json mget when dict is returned (#114)
      * fix: properly export (#116)
      * Extract param handling (#113)

    - update to v2.4.0:
      * Implement LCS (#111), BITOP (#110)
      * Fix bug checking type in scan_iter (#109)
      * Implement GETEX (#102)
      * Implement support for JSON.STRAPPEND (json command) (#98)
      * Implement JSON.STRLEN, JSON.TOGGLE and fix bugs with JSON.DEL (#96)
      * Implement PUBSUB CHANNELS, PUBSUB NUMSUB
      * Implement JSON.CLEAR (#87)
      * Support for redis-py v4.4.0
      * Implement json.mget (#85)
      * Initial json module support - JSON.GET, JSON.SET and JSON.DEL (#80)
      * fix: add nowait for asyncio disconnect (#76)
      * Refactor how commands are registered (#79)
      * Refactor tests from redispy4_plus (#77)
      * Remove support for aioredis separate from redis-py (redis-py versions
        4.1.2 and below). (#65)
      * Add support for redis-py v4.4rc4 (#73)
      * Add mypy support  (#74)
      * Implement support for zmscore by @the-wondersmith in #67
      * What's Changed
      * implement GETDEL and SINTERCARD support by @cunla in #57
      * Test get float-type behavior by @cunla in #59
      * Implement BZPOPMIN/BZPOPMAX support by @cunla in #60
    - drop fakeredis-pr54-fix-ensure_str.patch (upstream)

    - Update to 1.9.3
      * Removed python-six dependency
      * zadd support for GT/LT by @cunla in #49
      * Remove six dependency by @cunla in #51
      * Add host to conn_pool_args by @cunla in #51
    - Drop python-fakeredis-no-six.patch which was incomplete
      * all commits, including the missing ones in release now
    - Add fakeredis-pr54-fix-ensure_str.patch

    - use upstream
      https://github.com/cunla/fakeredis-py/pull/51/
    - modified patches
      % python-fakeredis-no-six.patch (refreshed)

    - version update to 1.9.1
      * Zrange byscore by @cunla in #44
      * Expire options by @cunla in #46
      * Enable redis7 support by @cunla in #42
    - added patches
      fix https://github.com/cunla/fakeredis-py/issues/50
      + python-fakeredis-no-six.patch

    - Update to 1.8.1
      * fix: allow redis 4.3.* by @terencehonles in #30
    - Release 1.8
      * Fix handling url with username and password by @cunla in #27
      * Refactor tests by @cunla in #28
    - Release 1.7.6
      * add IMOVE operation by @BGroever in #11
      * Add SMISMEMBER command by @OlegZv in #20
      * fix: work with redis.asyncio by @zhongkechen in #10
      * Migrate to poetry by @cunla in #12
      * Create annotation for redis4+ tests by @cunla in #14
      * Make aioredis and lupa optional dependencies by @cunla in #16
      * Remove aioredis requirement if redis-py 4.2+ by @ikornaselur in
        #19

    - update to 1.7.0
      * Change a number of corner-case behaviours to match Redis 6.2.6.
      * Fix DeprecationWarning for sampling from a set
      * Improved support for constructor arguments
      * Support redis-py 4
      * Add support for GET option to SET
      * PERSIST and EXPIRE should invalidate watches

    - Update to 1.6.1
      * #305 Some packaging modernisation
      * #306 Fix FakeRedisMixin.from_url for unix sockets
      * #308 Remove use of async_generator from tests
    - Release 1.6.0
      * #304 Support aioredis 2
      * #302 Switch CI from Travis CI to Github Actions

    - update to 1.5.2
     * support python 3.9
     * support aioredis

    - Disable py2 as upstream actually disabled python2 support competely
      * The syntax simply is not compatible

    - Update to 1.3.0:
      * No upstream changelog
    - python2 tests are dysfunctional, test with python3 only

    - Update to 1.0.5:
      * No upstream changelog

    - Update to 1.0.4:
      * various bugfixes all around

    - Update to v1.0.3
      * Support for redis 3.2
      (no effective changes in v1.0.2)

    - Initial spec for v1.0.1
    Changes in python-fixedint:

    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Fix capitalization in Summary
    - Limit Python files matched in %files section

    - Switch package to modern Python Stack on SLE-15
      + Add %{?sle15_python_module_pythons}
      + Drop %{?!python_module:%define python_module() python-%{**} python3-%{**}}

    - Initial build
      + Version 0.2.0
    Changes in python-httplib2:
    - require setuptools

    - Clean up SPEC file.

    - Add %{?sle15_python_module_pythons}

    - update to 0.22.0:
      * https: disable_ssl_certificate_validation caused
        ValueError: Cannot set verify_mode to CERT_NONE when
        check_hostname is enabled

    - Update to 0.21.0:
      * http: `Content-Encoding: deflate` must accept zlib encapsulation
      * https://github.com/httplib2/httplib2/pull/230
      * Begin support and CI against CPython 3.10 and 3.11.

    - update to 0.20.4:
      proxy: support proxy urls with ipv6 address
      Tests compatible with Python3.10 and recent pytest.

    - add pyparsing dependency

    - update to 0.20.2:
      auth: support pyparsing v3
      proxy: correct extraction of errno from pysocks ProxyConnectionError
      IMPORTANT cacerts: remove expired DST Root CA X3, add ISRG Root X1, X2

    - update to 0.19.1:
      * auth header parsing performance optimizations; Thanks to Paul McGuire
      * Use mock from the standard library on Python>=3.3

      set first, othewise a 'ValueError: Cannot set
      verify_mode to CERT_NONE when check_hostname
      instead (bnc#761162)
              item not in cache
    - initial version of python-httplib2 (0.2.0)
    Changes in python-httpretty:
    - Add patch 0001-Fix-test_417_openssl.py-if-pyOpenSSL-not-available.patch:
      * Fix tests without pyOpenSSL support in urllib3

    - Allow building with python-urllib3 >= 2.x

    - Do not use python-boto3 when building in SLE where it's currently
      not available for python311

    - Add %{?sle15_python_module_pythons}

    - skip failing testsuite tests after requests update

    - Add patch relax-test-callback-response.patch:
      * Relax timeout for test_callback_response (bsc#1209571)

    - Add patch 460-miliseconds_tests.patch (gh#gabrielfalcao/HTTPretty#460):
      * Correct tests for s390x and aarch64 because of timeout failures
        after 2 miliseconds

    - Fix test suite:
      * Remove nose idioms
      * Remove outdated test skips

    - Add patch double-slash-paths.patch:
      * http.request may replace // with /, handle that in the testcase.

    - Add 453-fix-tests-pytest.patch (gh#gabrielfalcao/HTTPretty#449)
      to make tests compatible with pytest.

    - Add patch remove-mock.patch:
      * Use unittest.mock in the functional tests.

    - specfile:
      * update copyright year
    - update to version 1.1.4:
      * Bugfix: #435 Fallback to WARNING when logging.getLogger().level is
        None.
    - changes from version 1.1.3:
      * Bugfix: #430 Respect socket timeout.
    - changes from version 1.1.2:
      * Bugfix: #426 Segmentation fault when running against a large
        amount of tests with pytest --mypy.
    - changes from version 1.1.1:
      * Bugfix: httpretty.disable() injects pyopenssl into
        :py:mod:`urllib3` even if it originally wasn't #417
      * Bugfix: 'Incompatibility with boto3 S3 put_object' #416
      * Bugfix: 'Regular expression for URL -> TypeError: wrap_socket()
        missing 1 required' #413
      * Bugfix: 'Making requests to non-stadard port throws TimeoutError
        '#387
    - changes from version 1.1.0:
      * Feature: Display mismatched URL within UnmockedError whenever
        possible. #388
      * Feature: Display mismatched URL via logging. #419
      * Add new properties to :py:class:`httpretty.core.HTTPrettyRequest`
        (protocol, host, url, path, method).

    - Updater to 1.0.5
      * Bugfix: Support socket.socketpair() . #402
      * Bugfix: Prevent exceptions from re-applying monkey patches.
        #406
    - Release 1.0.4
      * Python 3.8 and 3.9 support. #407

    - Update to 1.0.3
      * Fix compatibility with urllib3>=1.26. #410

    - Replace nose with nose2

    - avoid reading DNS resolver settings
      gh#gabrielfalcao/HTTPretty#405
    - remove unnecessary test packages

    - Update to 1.0.2
      * Drop Python 2 support.
      * Fix usage with redis and improve overall real-socket passthrough.
      * Fix TypeError: wrap_socket() missing 1 required positional argument: 'sock'.
      * Fix simple typo: neighter -> neither.
      * Updated documentation for register_uri concerning using ports.
      * Clarify relation between ``enabled`` and ``httprettized`` in API docs.
      * Align signature with builtin socket.

    - Version update to 0.9.6:
      * Many fixes all around
      * Support for python 3.7
    - Make sure we really run the tests

    - Remove superfluous devel dependency for noarch package

    Changes in python-javaproperties:
    - Switch package to modern Python Stack on SLE-15
      + Add %{?sle15_python_module_pythons}

    - version update to 0.8.1
      v0.8.1 (2021-10-05)
      -------------------
      - Fix a typing issue in Python 3.9
      - Support Python 3.10

      v0.8.0 (2020-11-28)
      -------------------
      - Drop support for Python 2.7, 3.4, and 3.5
      - Support Python 3.9
      - `ensure_ascii` parameter added to `PropertiesFile.dump()` and
        `PropertiesFile.dumps()`
      - **Bugfix**: When parsing XML input, empty `<entry>` tags now produce an empty
        string as a value, not `None`
      - Added type annotations
      - `Properties` and `PropertiesFile` no longer raise `TypeError` when given a
        non-string key or value, as type correctness is now expected to be enforced
        through static type checking
      - The `PropertiesElement` classes returned by `parse()` are no longer
        subclasses of `namedtuple`, but they can still be iterated over to retrieve
        their fields like a tuple
    - python-six is not required
    Changes in python-jsondiff:
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - Add %{?sle15_python_module_pythons}

    - Update to version 2.0.0
      * Removed deprecated function
      * Remove deprecated jsondiff entry point
    - from version 1.3.1
      * Optionally allow different escape_str than '$'
      * Clarified the readme, closes #23
      * Fixed readme
    - Remove jsondiff command from %install, %post, %postun and %files sections
    Changes in python-knack:
    - Switch package to modern Python Stack on SLE-15
      + Add %{?sle15_python_module_pythons}
      + Drop %{?!python_module:%define python_module() python-%{**} python3-%{**}}
      + Drop %define skip_python2 1

    - Update to version 0.11.0
      * Declare support for Python 3.11 and drop support for Python 3.7 (#275)
      * Stop converting argument's `bool` default value to `DefaultInt` (#273)

    - Update to version 0.10.1
      * Support bytearray serialization (#268)

    - Update to version 0.10.0
      * Enable Virtual Terminal mode on legacy Windows terminal
        to support ANSI escape sequences (#265)
      * Drop Python 3.6 support (#259)

    - python-mock is not required for build
    Changes in python-marshmallow:
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - update to 3.20.2:
      * Bug fixes: - Fix Nested field type hint for lambda Schema
        types (:pr:`2164`).
      * Other changes: - Officially support Python 3.12 (:pr:`2188`).

    - update to 3.20.1:
      * Fix call to ``get_declared_fields``: pass ``dict_cls`` again
      * Add ``absolute`` parameter to ``URL`` validator and ``Url``
      * Use Abstract Base Classes to define ``FieldABC`` and
        ``SchemaABC``
      * Use `OrderedSet` as default `set_class`. Schemas are now
        ordered by default.
      * Handle ``OSError`` and ``OverflowError`` in
        ``utils.from_timestamp`` (:pr:`2102`).
      * Fix the default inheritance of nested partial schemas
      * Officially support Python 3.11 (:pr:`2067`).
      * Drop support for Python 3.7 (:pr:`2135`).

    - Switch documentation to be within the main package on SLE15
    - rename docs subpackage to the more common doc name
    - Update to 3.19.0
      * Add timestamp and timestamp_ms formats to fields.DateTime (#612). Thanks @vgavro for    the suggestion
    and thanks @vanHoi for the PR.

    Changes in python-opencensus:
    - Add Obsoletes for old python3 package on SLE-15
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Update to 0.11.4
      * Changed bit-mapping for `httpx` and `fastapi` integrations
    - Refresh patches for new version
      * opencensus-pr1002-remove-mock.patch
    - Switch package to modern Python Stack on SLE-15
      * Add %{?sle15_python_module_pythons}
      * Drop %{?!python_module:%define python_module() python-%{**} python3-%{**}}

    - update to 0.11.3
      * Updated azure modules
    - sorry, six is still needed :(

    - update to 0.11.2:
      * Updated `azure`, `fastapi`,`flask` modules
      * Updated `azure`, `httpx` modules

    - Update to 0.11.0
      * Updated `azure`, `context`, `flask`, `requests` modules
    - from version 0.10.0
      * Add kwargs to derived gauge (#1135)
    - from version 0.9.0
      * Make sure handler.flush() doesn't deadlock (#1112)
    - Refresh patches for new version
      * opencensus-pr1002-remove-mock.patch
    - Update Requires from setup.py

    Changes in python-opencensus-context:
    - Clean up the SPEC file
    - Switch package to modern Python Stack on SLE-15
      + Add %{?sle15_python_module_pythons}
      + Drop %{?!python_module:%define python_module() python-%{**} python3-%{**}}
    - Update to 0.1.3
      * Move `version.py` file into `runtime_context` folder (#1143)
    Changes in python-opencensus-ext-threading:
    - Switch package to modern Python Stack on SLE-15
      + Add %{?sle15_python_module_pythons}
      + Drop %{?!python_module:%define python_module() python-%{**} python3-%{**}}
      + Drop build support for Python 2.x
    Changes in python-opentelemetry-api:
    - update to 1.23.0:
      * Use Attribute rather than boundattribute in logrecord (#3567)
      * Fix flush error when no LoggerProvider configured for LoggingHandler (#3608)
      * Fix OTLPMetricExporter ignores preferred_aggregation property (#3603)
      * Logs: set observed_timestamp field (#3565)
      * Add missing Resource SchemaURL in OTLP exporters (#3652)
      * Fix loglevel warning text (#3566)
      * Prometheus Exporter string representation for target_info labels (#3659)
      * Logs: ObservedTimestamp field is missing in console exporter output (#3564)
      * Fix explicit bucket histogram aggregation (#3429)
      * Add code.lineno, code.function and code.filepath to all logs (#3645)
      * Add Synchronous Gauge instrument (#3462)
      * Drop support for 3.7 (#3668)
      * Include key in attribute sequence warning (#3639)
      * Upgrade markupsafe, Flask and related dependencies to dev and test
        environments (#3609)
      * Handle HTTP 2XX responses as successful in OTLP exporters (#3623)
      * Improve Resource Detector timeout messaging (#3645)
      * Add Proxy classes for logging (#3575)
      * Remove dependency on 'backoff' library (#3679)

    - update to 1.22.0:
      * Prometheus exporter sanitize info metric (#3572)
      * Remove Jaeger exporters (#3554)
      * Log stacktrace on `UNKNOWN` status OTLP export error  (#3536)
      * Fix OTLPExporterMixin shutdown timeout period (#3524)
      * Handle `taskName` `logrecord` attribute (#3557)

    - update to 1.21.0:
      * Fix `SumAggregation`(#3390)
      * Fix handling of empty metric collection cycles (#3335)
      * Fix error when no LoggerProvider configured for
        LoggingHandler (#3423)
      * Make `opentelemetry_metrics_exporter` entrypoint support pull
        exporters (#3428)
      * Allow instrument names to have '/' and up to 255 characters
        (#3442)
      * Do not load Resource on sdk import (#3447)
      * Update semantic conventions to version 1.21.0 (#3251)
      * Add missing schema_url in global api for logging and metrics
        (#3251)
      * Prometheus exporter support for auto instrumentation  (#3413)
      * Modify Prometheus exporter to translate non-monotonic Sums
        into Gauges (#3306)
      * Update the body type in the log ($3343)
      * Add max_scale option to Exponential Bucket Histogram
        Aggregation  (#3323)
      * Use BoundedAttributes instead of raw dict to extract
        attributes from LogRecord (#3310)
      * Support dropped_attributes_count in LogRecord and exporters
        (#3351)
      * Add unit to view instrument selection criteria (#3341)
      * Upgrade opentelemetry-proto to 0.20 and regen #3355)
      * Include endpoint in Grpc transient error warning #3362)
      * Fixed bug where logging export is tracked as trace #3375)
      * Select histogram aggregation with an environment variable
      * Move Protobuf encoding to its own package (#3169)
      * Add experimental feature to detect resource detectors in auto
        instrumentation (#3181)
      * Fix exporting of ExponentialBucketHistogramAggregation from
        opentelemetry.sdk.metrics.view (#3240)
      * Fix headers types mismatch for OTLP Exporters (#3226)
      * Fix suppress instrumentation for log batch processor (#3223)
      * Add speced out environment variables and arguments for
        BatchLogRecordProcessor (#3237)

        - Fix `ParentBased` sampler for implicit parent spans. Fix also `trace_state`
          erasure for dropped spans or spans sampled by the `TraceIdRatioBased` sampler.
    Changes in python-opentelemetry-sdk:

    - Add missing python-wheel build dependency to BuildRequires

    - update to 1.23.0:
      * Use Attribute rather than boundattribute in logrecord (#3567)
      * Fix flush error when no LoggerProvider configured for LoggingHandler (#3608)
      * Fix OTLPMetricExporter ignores preferred_aggregation property (#3603)
      * Logs: set observed_timestamp field (#3565)
      * Add missing Resource SchemaURL in OTLP exporters (#3652)
      * Fix loglevel warning text (#3566)
      * Prometheus Exporter string representation for target_info labels (#3659)
      * Logs: ObservedTimestamp field is missing in console exporter output (#3564)
      * Fix explicit bucket histogram aggregation (#3429)
      * Add code.lineno, code.function and code.filepath to all logs (#3645)
      * Add Synchronous Gauge instrument (#3462)
      * Drop support for 3.7 (#3668)
      * Include key in attribute sequence warning (#3639)
      * Upgrade markupsafe, Flask and related dependencies to dev and test
        environments (#3609)
      * Handle HTTP 2XX responses as successful in OTLP exporters (#3623)
      * Improve Resource Detector timeout messaging (#3645)
      * Add Proxy classes for logging (#3575)
      * Remove dependency on 'backoff' library (#3679)

    - update to 1.23.0:
      * Use Attribute rather than boundattribute in logrecord (#3567)
      * Fix flush error when no LoggerProvider configured for LoggingHandler (#3608)
      * Fix OTLPMetricExporter ignores preferred_aggregation property (#3603)
      * Logs: set observed_timestamp field (#3565)
      * Add missing Resource SchemaURL in OTLP exporters (#3652)
      * Fix loglevel warning text (#3566)
      * Prometheus Exporter string representation for target_info labels (#3659)
      * Logs: ObservedTimestamp field is missing in console exporter output (#3564)
      * Fix explicit bucket histogram aggregation (#3429)
      * Add code.lineno, code.function and code.filepath to all logs (#3645)
      * Add Synchronous Gauge instrument (#3462)
      * Drop support for 3.7 (#3668)
      * Include key in attribute sequence warning (#3639)
      * Upgrade markupsafe, Flask and related dependencies to dev and test
        environments (#3609)
      * Handle HTTP 2XX responses as successful in OTLP exporters (#3623)
      * Improve Resource Detector timeout messaging (#3645)
      * Add Proxy classes for logging (#3575)
      * Remove dependency on 'backoff' library (#3679)

    - Switch package to modern Python Stack on SLE-15
      + Add %{?sle15_python_module_pythons}

    - Initial package (1.22.0)
    Changes in python-opentelemetry-semantic-conventions:

    - update to 0.44b0:
      * Use Attribute rather than boundattribute in logrecord (#3567)
      * Fix flush error when no LoggerProvider configured for LoggingHandler (#3608)
      * Fix OTLPMetricExporter ignores preferred_aggregation property (#3603)
      * Logs: set observed_timestamp field (#3565)
      * Add missing Resource SchemaURL in OTLP exporters (#3652)
      * Fix loglevel warning text (#3566)
      * Prometheus Exporter string representation for target_info labels (#3659)
      * Logs: ObservedTimestamp field is missing in console exporter output (#3564)
      * Fix explicit bucket histogram aggregation (#3429)
      * Add code.lineno, code.function and code.filepath to all logs (#3645)
      * Add Synchronous Gauge instrument (#3462)
      * Drop support for 3.7 (#3668)
      * Include key in attribute sequence warning (#3639)
      * Upgrade markupsafe, Flask and related dependencies to dev and test
        environments (#3609)
      * Handle HTTP 2XX responses as successful in OTLP exporters (#3623)
      * Improve Resource Detector timeout messaging (#3645)
      * Add Proxy classes for logging (#3575)
      * Remove dependency on 'backoff' library (#3679)

    - update to 0.43b0:
      * Prometheus exporter sanitize info metric
      * Remove Jaeger exporters
      * Log stacktrace on `UNKNOWN` status OTLP export error
      * Fix OTLPExporterMixin shutdown timeout period
      * Handle `taskName` `logrecord` attribute
      * Fix `SumAggregation`
      * Fix handling of empty metric collection cycles
      * Fix error when no LoggerProvider configured for
        LoggingHandler
      * Make `opentelemetry_metrics_exporter` entrypoint support pull
        exporters
      * Allow instrument names to have '/' and up to 255 characters
      * Do not load Resource on sdk import
      * Update semantic conventions to version 1.21.0
      * Add missing schema_url in global api for logging and metrics
      * Prometheus exporter support for auto instrumentation
      * Drop `setuptools` runtime requirement.
      * Update the body type in the log ($3343)
      * Add max_scale option to Exponential Bucket Histogram
        Aggregation
      * Use BoundedAttributes instead of raw dict to extract
        attributes from LogRecord
      * Support dropped_attributes_count in LogRecord and exporters
      * Add unit to view instrument selection criteria
      * Upgrade opentelemetry-proto to 0.20 and regen #3355)
      * Include endpoint in Grpc transient error warning #3362)
      * Fixed bug where logging export is tracked as trace #3375)
      * Select histogram aggregation with an environment variable
      * Move Protobuf encoding to its own package
      * Add experimental feature to detect resource detectors in auto
        instrumentation
      * Fix exporting of ExponentialBucketHistogramAggregation from
        opentelemetry.sdk.metrics.view
      * Fix headers types mismatch for OTLP Exporters
      * Fix suppress instrumentation for log batch processor
      * Add speced out environment variables and arguments for
        BatchLogRecordProcessor

    - Initial build
      + Version 0.25b2
    Changes in python-opentelemetry-test-utils:

    - update to 0.44b0:
      * Use Attribute rather than boundattribute in logrecord (#3567)
      * Fix flush error when no LoggerProvider configured for LoggingHandler (#3608)
      * Fix OTLPMetricExporter ignores preferred_aggregation property (#3603)
      * Logs: set observed_timestamp field (#3565)
      * Add missing Resource SchemaURL in OTLP exporters (#3652)
      * Fix loglevel warning text (#3566)
      * Prometheus Exporter string representation for target_info labels (#3659)
      * Logs: ObservedTimestamp field is missing in console exporter output (#3564)
      * Fix explicit bucket histogram aggregation (#3429)
      * Add code.lineno, code.function and code.filepath to all logs (#3645)
      * Add Synchronous Gauge instrument (#3462)
      * Drop support for 3.7 (#3668)
      * Include key in attribute sequence warning (#3639)
      * Upgrade markupsafe, Flask and related dependencies to dev and test
        environments (#3609)
      * Handle HTTP 2XX responses as successful in OTLP exporters (#3623)
      * Improve Resource Detector timeout messaging (#3645)
      * Add Proxy classes for logging (#3575)
      * Remove dependency on 'backoff' library (#3679)

    - Initial package (0.43b0)
    Changes in python-pycomposefile:

    - Switch package to modern Python Stack on SLE-15
      + Add %{?sle15_python_module_pythons}

    - Initial build
      + Version 0.0.30
    Changes in python-pydash:

    - Switch package to modern Python Stack on SLE-15
      + Add %{?sle15_python_module_pythons}
      + Drop %{?!python_module:%define python_module() python-%{**} python3-%{**}}

    - Update to version 6.0.2
      * Only prevent access to object paths containing ``__globals__`` or
        ``__builtins__`` instead of all dunder-methods for non-dict/list
        objects.
    - from version 6.0.1
      * Fix exception raised due to mishandling of non-string keys in functions
        like ``get()`` for non-dict/list objects that used integer index references
        like ``'[0]'``.
    - from version 6.0.0
      * Prevent access to object paths containing dunder-methods in functions like
        ``get()`` for non-dict/list objects. Attempting to access dunder-methods
        using get-path keys will raise a ``KeyError`` (e.g. ``get(SomeClass(),
        '__init__'`` will raise). Access to dict keys are unaffected (e.g.
        ``get({'__init__': True}, '__init__')`` will return ``True``).
        (**breaking change**)
      * Add support for Python 3.11.
      * Drop support for Python 3.6 (**breaking change**)
    - from version 5.1.2
      * Remove unnecessary type check and conversion for ``exceptions``
        argument in ``pydash.retry``.
    - from version 5.1.1
      * Add support for Python 3.10.
      * Fix timing assertion issue in test for ``pydash.delay`` where it could
        fail on certain environments.
    - Switch build system from setuptools to pyproject.toml
    - Update BuildRequires from pyproject.toml

    - version update to 5.1.0
      v5.1.0 (2021-10-02)
      -------------------
      - Support matches-style callbacks on non-dictionary objects that are compatible with ``pydash.get`` in
    functions like ``pydash.find``.
      v5.0.2 (2021-07-15)
      -------------------
      - Fix compatibility issue between ``pydash.py_`` / ``pydash._`` and ``typing.Protocol`` +
    ``typing.runtime_checkable``
        that caused an exception to be raised for ``isinstance(py_, SomeRuntimeCheckableProtocol)``.
      v5.0.1 (2021-06-27)
      -------------------
      - Fix bug in ``merge_with`` that prevented custom iteratee from being used when recursively merging.
    Thanks weineel_!
      v5.0.0 (2021-03-29)
      -------------------
      - Drop support for Python 2.7. (**breaking change**)
      - Improve Unicode word splitting in string functions to be inline with Lodash. Thanks mervynlee94_!
    (**breaking change**)
        - ``camel_case``
        - ``human_case``
        - ``kebab_case``
        - ``lower_case``
        - ``pascal_case``
        - ``separator_case``
        - ``slugify``
        - ``snake_case``
        - ``start_case``
        - ``upper_case``
      - Optimize regular expression constants used in ``pydash.strings`` by pre-compiling them to regular
    expression pattern objects.
      v4.9.3 (2021-03-03)
      -------------------
      - Fix regression introduced in ``v4.8.0`` that caused ``merge`` and ``merge_with`` to raise an exception
    when passing ``None``
        as the first argument.
      v4.9.2 (2020-12-24)
      -------------------
      - Fix regression introduced in ``v4.9.1`` that broke ``pydash.get`` for dictionaries and dot-delimited
    keys that reference
        integer dict-keys.
      v4.9.1 (2020-12-14)
      -------------------
      - Fix bug in ``get/has`` that caused ``defaultdict`` objects to get populated on key access.
      v4.9.0 (2020-10-27)
      -------------------
      - Add ``default_to_any``. Thanks gonzalonaveira_!
      - Fix mishandling of key names containing ``\.`` in ``set_``, ``set_with``, and ``update_with`` where
    the ``.`` was not
        treated as a literal value within the key name. Thanks zhaowb_!
    - python-mock is not required for build

    - Activate test suite
    - Update to v4.8.0

    - Initial spec for v4.7.6
    Changes in python-redis:
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install

    - add https://github.com/redis/redis-py/pull/3005 as
      Close-various-objects-created-during-asyncio-tests.patch
      to fix tests for python 3.12

    - Add patch to increase timeouts in s390x where tests take longer
      to run:
      * increase-test-timeout.patch

    - Disable broken tests for ppc64le, bsc#1216606

    - Add pytest.ini source needed to run tests
    - Remove/disable broken tests because of suse environment

    - drop tox.ini. seems it does no longer exist in 5.0.1
    - add support to easily disable the testsuite at build time

    - update to 5.0.1
      - New Features
        - Provide aclose() / close() for classes requiring lifetime
          management (#2898)
        - Add support for ModuleCommands in cluster (#2951)
        - Add support for multiple values in RPUSHX (#2949)
        - Add Redis.from_pool() class method, for explicitly owning and
          closing a ConnectionPool (#2913)
      - Bug Fixes
        - Fixing monitor parsing for messages containing specific
          substrings (#2950)
        - Cluster determine slot command name need to be upper (#2919)
        - Support timeout = 0 in search query (#2934)
        - Fix async sentinel: add push_request keyword argument to
          read_response (#2922)
        - Fix protocol checking for search commands (#2923)
        - Fix: SentinelManagedConnection.read_response() got an
          unexpected keyword argument 'push_request' (#2894)
        - Fix: automatically close connection pool for async Sentinel
          (#2900)
        - Save a reference to created async tasks, to avoid tasks
          potentially disappearing (#2816)
        - Avoid reference cycling by the garbage collector during
          response reading (#2932)
      - Maintenance
        - Type hint improvements (#2952)
        - Replace clear_connect_callbacks with
          _deregister_connect_callback (#2955)
        - Async fixes, remove del and other things (#2870)
        - Add pagination, sorting and grouping examples to search json
          example (#2890)
        - Remove process-id checks from asyncio. Asyncio and fork()
          does not mix. (#2911)
        - Fix resource usage and cleanup Mocks in the unit tests
          (#2936)
        - Remove mentions of tox (#2929)
        - Add 7.2 to supported Redis versions (#2896)
        - Fix resource warnings in unit tests (#2899)
        - Fix typo in redis-stream-example.ipynb (#2918)
        - Deprecate RedisGraph (#2927)
        - Fix redis 7.2.0 tests (#2902)
        - Fix test_scorer (search) (#2920)
    - changes from 5.0.0
      - What's new?
        - Triggers and Functions support Triggers and Functions allow
          you to execute server-side functions triggered when key
          values are modified or created in Redis, a stream entry
          arrival, or explicitly calling them. Simply put, you can
          replace Lua scripts with easy-to-develop JavaScript or
          TypeScript code. Move your business logic closer to the data
          to ensure a lower latency, and forget about updating
          dependent key values manually in your code. Try it for
          yourself with Quick start
        - Full Redis 7.2 and RESP3 support
        - Python 3.7 End-of-Life
          - Python 3.7 has reached its end-of-life (EOL) as of June
            2023. This means that starting from this date, Python 3.7
            will no longer receive any updates, including security
            patches, bug fixes, or improvements. If you continue to use
            Python 3.7 post-EOL, you may expose your projects and
            systems to potential security vulnerabilities. We ended its
            support in this version and strongly recommend migrating to
            Python 3.10.
      - Bug Fixes
        - Fix timeout retrying on pipeline execution (#2812)
        - Fix socket garbage collection (#2859)
      - Maintenance
        - Updating client license to clear, MIT (#2884)
        - Add py.typed in accordance with PEP-561 (#2738)
        - Dependabot label change (#2880)
        - Fix type hints in SearchCommands (#2817)
        - Add sync modules (except search) tests to cluster CI (#2850)
        - Fix a duplicate word in CONTRIBUTING.md (#2848)
        - Fixing doc builds (#2869)
        - Change cluster docker to edge and enable debug command
          (#2853)
    - changes from 4.6.0
      - Experimental Features
        - Support JSON.MERGE command (#2761)
        - Support JSON.MSET command (#2766)
      - New Features
        - Extract abstract async connection class (#2734)
        - Add support for WAITAOF (#2760)
        - Introduce OutOfMemoryError exception for Redis write command rejections due to OOM errors (#2778)
        - Add WITHSCORE argument to ZRANK (#2758)
      - Bug Fixes
        - Fix dead weakref in sentinel connection causing ReferenceError (#2767) (#2771)
        - Fix Key Error in parse_xinfo_stream (#2788)
        - Remove unnecessary __del__ handlers (#2755)
        - Added support for missing argument to SentinelManagedConnection.read_response() (#2756)
      - Maintenance
        - Fix type hint for retry_on_error in async cluster (#2804)
        - Clean up documents and fix some redirects (#2801)
        - Add unit tests for the connect method of all Redis connection classes (#2631)
        - Docstring formatting fix (#2796)

    - update to 4.5.5:
      * Add support for CLIENT NO-TOUCH
      * Add support for CLUSTER MYSHARDID
      * Add 'address_remap' feature to RedisCluster
      * Add WITHSCORES argument to ZREVRANK command
      * Improve error output for master discovery
      * Fix XADD: allow non negative maxlen
      * Fix create single connection client from url
      * Optionally disable disconnects in read_response
      * Fix SLOWLOG GET return value
      * Fix potential race condition during disconnection
      * Return response in case of KeyError
      * Fix incorrect usage of once flag in async Sentinel
      * Fix memory leak caused by hiredis in asyncio case
      * Really do not use asyncio's timeout lib before 3.11.2

    - add sle15_python_module_pythons

    - Update to 4.5.4:
      * Security
        + Cancelling an async future does not, properly trigger, leading to a
          potential data leak in specific cases. (CVE-2023-28858, bsc#1209811)
        + Cancelling an async future does not, properly trigger, leading to a
          potential data leak in specific cases. (CVE-2023-28859, bsc#1209812)
      * New Features
        + Introduce AbstractConnection so that UnixDomainSocketConnection can
          call super().init (#2588)
        + Added queue_class to REDIS_ALLOWED_KEYS (#2577)
        + Made search document subscriptable (#2615)
        + Sped up the protocol parsing (#2596)
        + Use hiredis::pack_command to serialized the commands. (#2570)
        + Add support for unlink in cluster pipeline (#2562)
      * Bug Fixes
        + Fixing cancelled async futures (#2666)
        + Fix: do not use asyncio's timeout lib before 3.11.2 (#2659)
        + Fix UDS in v4.5.2: UnixDomainSocketConnection missing constructor
          argument (#2630)
        + CWE-404 AsyncIO Race Condition Fix (#2624, #2579)
        + Fix behaviour of async PythonParser to match RedisParser as for
          issue #2349 (#2582)
        + Replace async_timeout by asyncio.timeout (#2602)
        + Update json().arrindex() default values (#2611)
        + Fix #2581 UnixDomainSocketConnection object has no attribute
          _command_packer (#2583)
        + Fix issue with pack_commands returning an empty byte sequence (#2416)
        + Async HiredisParser should finish parsing after a
          Connection.disconnect() (#2557)
        + Check for none, prior to raising exception (#2569)
        + Tuple function cannot be passed more than one argument (#2573)
        + Synchronise concurrent command calls to single-client to single-client
          mode (#2568)
        + Async: added 'blocking' argument to call lock method (#2454)
        + Added a replacement for the default cluster node in the event of
          failure. (#2463)
        + Fixed geosearch: Wrong number of arguments for geosearch command (#2464)
    - Clean up BuildRequires and Requires.

    - Disable broken test test_xautoclaim gh#redis/redis-py#2554
    - udpate to 4.3.5:
      * Add support for TIMESERIES 1.8 (#2296)
      * Graph - add counters for removed labels and properties (#2292)
      * Add support for TDIGEST.QUANTILE extensions (#2317)
      * Add TDIGEST.TRIMMED_MEAN (#2300)
      * Add support for async GRAPH module (#2273)
      * Support TDIGEST.MERGESTORE and make compression optional on TDIGEST.CREATE
        (#2319)
      * Adding reserve as an alias for create, so that we have BF.RESERVE and
        CF.RESERVE accuratenly supported (#2331)
      * Fix async connection.is_connected to return a boolean value (#2278)
      * Fix: workaround asyncio bug on connection reset by peer (#2259)
      * Fix crash: key expire while search (#2270)
      * Async cluster: fix concurrent pipeline (#2280)
      * Fix async SEARCH pipeline (#2316)
      * Fix KeyError in async cluster - initialize before execute multi key
        commands (#2439)
      * Supply chain risk reduction: remove dependency on library named deprecated
        (#2386)
      * Search test - Ignore order of the items in the response (#2322)
      * Fix GRAPH.LIST & TDIGEST.QUANTILE tests (#2335)
      * Fix TimeSeries range aggregation (twa) tests (#2358)
      * Mark TOPK.COUNT as deprecated (#2363)

    - update to 4.3.4:
      * Fix backward compatibility from 4.3.2 in Lock.acquire()
      * Fix XAUTOCLAIM to return the full response, instead of only keys 2+
      * Added dynamic_startup_nodes configuration to RedisCluster.
      * Fix retries in async mode
      * Async cluster: fix simultaneous initialize
      * Uppercased commands in CommandsParser.get_keys
      * Late eval of the skip condition in async tests
      * Reuse the old nodes' connections when a cluster topology refresh is being done
      * Docs: add pipeline examples
      * Correct retention_msecs value
      * Cluster: use pipeline to execute split commands
      * Docs: Add a note about client_setname and client_name difference

    - Delete unused redismod.conf, remove duplicate Source entry for
      tox.ini

    - Add redismod.conf and tox.ini as Sources to SPEC file.

    - Update to version 4.3.3
      * Fix Lock crash, and versioning 4.3.3 (#2210)
      * Async cluster: improve docs (#2208)
    - Release 4.3.2
      * SHUTDOWN - add support for the new NOW, FORCE and ABORT modifiers (#2150)
      * Adding pipeline support for async cluster (#2199)
      * Support CF.MEXISTS + Clean bf/commands.py (#2184)
      * Extending query_params for FT.PROFILE (#2198)
      * Implementing ClusterPipeline Lock (#2190)
      * Set default response_callbacks to redis.asyncio.cluster.ClusterNode (#2201)
      * Add default None for maxlen at xtrim command (#2188)
      * Async cluster: add/update typing (#2195)
      * Changed list type to single element type (#2203)
      * Made sync lock consistent and added types to it (#2137)
      * Async cluster: optimisations (#2205)
      * Fix typos in README (#2206)
      * Fix modules links to https://redis.io/commands/ (#2185)

    - Update to version 4.3.1
        * Allow negative `retries` for `Retry` class to retry forever
        * Add `items` parameter to `hset` signature
        * Create codeql-analysis.yml (#1988). Thanks @chayim
        * Add limited support for Lua scripting with RedisCluster
        * Implement `.lock()` method on RedisCluster
        * Fix cursor returned by SCAN for RedisCluster & change default
          target to PRIMARIES
        * Fix scan_iter for RedisCluster
        * Remove verbose logging when initializing ClusterPubSub,
          ClusterPipeline or RedisCluster
        * Fix broken connection writer lock-up for asyncio (#2065)
        * Fix auth bug when provided with no username (#2086)
    - Release 4.1.3
        * Fix flushdb and flushall (#1926)
        * Add redis5 and redis4 dockers (#1871)
        * Change json.clear test multi to be up to date with redisjson
          (#1922)
        * Fixing volume for unstable_cluster docker (#1914)
        * Update changes file with changes since 4.0.0-beta2 (#1915)
    - Release 4.1.2
        * Invalid OCSP certificates should raise ConnectionError on
          failed validation (#1907)
        * Added retry mechanism on socket timeouts when connecting to
          the server (#1895)
        * LMOVE, BLMOVE return incorrect responses (#1906)
        * Fixing AttributeError in UnixDomainSocketConnection (#1903)
        * Fixing TypeError in GraphCommands.explain (#1901)
        * For tests, increasing wait time for the cluster (#1908)
        * Increased pubsub's wait_for_messages timeout to prevent flaky
          tests (#1893)
        * README code snippets formatted to highlight properly (#1888)
        * Fix link in the main page (#1897)
        * Documentation fixes: JSON Example, SSL Connection Examples,
          RTD version (#1887)
        * Direct link to readthedocs (#1885)
    - Release 4.1.1
        * Add retries to connections in Sentinel Pools (#1879)
        * OCSP Stapling Support (#1873)
        * Define incr/decr as aliases of incrby/decrby (#1874)
        * FT.CREATE - support MAXTEXTFIELDS, TEMPORARY, NOHL, NOFREQS,
          SKIPINITIALSCAN (#1847)
        * Timeseries docs fix (#1877)
        * get_connection: catch OSError too (#1832)
        * Set keys var otherwise variable not created (#1853)
        * Clusters should optionally require full slot coverage (#1845)
        * Triple quote docstrings in client.py PEP 257 (#1876)
        * syncing requirements (#1870)
        * Typo and typing in GraphCommands documentation (#1855)
        * Allowing poetry and redis-py to install together (#1854)
        * setup.py: Add project_urls for PyPI (#1867)
        * Support test with redis unstable docker (#1850)
        * Connection examples (#1835)
        * Documentation cleanup (#1841)
    - Release 4.1.0
        * OCSP stapling support (#1820)
        * Support for SELECT (#1825)
        * Support for specifying error types with retry (#1817)
        * Support for RESET command since Redis 6.2.0 (#1824)
        * Support CLIENT TRACKING (#1612)
        * Support WRITE in CLIENT PAUSE (#1549)
        * JSON set_file and set_path support (#1818)
        * Allow ssl_ca_path with rediss:// urls (#1814)
        * Support for password-encrypted SSL private keys (#1782)
        * Support SYNC and PSYNC (#1741)
        * Retry on error exception and timeout fixes (#1821)
        * Fixing read race condition during pubsub (#1737)
        * Fixing exception in listen (#1823)
        * Fixed MovedError, and stopped iterating through startup nodes
          when slots are fully covered (#1819)
        * Socket not closing after server disconnect (#1797)
        * Single sourcing the package version (#1791)
        * Ensure redis_connect_func is set on uds connection (#1794)
        * SRTALGO - Skip for redis versions greater than 7.0.0 (#1831)
        * Documentation updates (#1822)
        * Add CI action to install package from repository commit hash
          (#1781) (#1790)
        * Fix link in lmove docstring (#1793)
        * Disabling JSON.DEBUG tests (#1787)
        * Migrated targeted nodes to kwargs in Cluster Mode (#1762)
        * Added support for MONITOR in clusters (#1756)
        * Adding ROLE Command (#1610)
        * Integrate RedisBloom support (#1683)
        * Adding RedisGraph support (#1556)
        * Allow overriding connection class via keyword arguments
          (#1752)
        * Aggregation LOAD * support for RediSearch (#1735)
        * Adding cluster, bloom, and graph docs (#1779)
        * Add packaging to setup_requires, and use >= to play nice to
          setup.py (fixes #1625) (#1780)
        * Fixing the license link in the readme (#1778)
        * Removing distutils from tests (#1773)
        * Fix cluster ACL tests (#1774)
        * Improved RedisCluster's reinitialize_steps and documentation
          (#1765)
        * Added black and isort (#1734)
        * Link Documents for all module commands (#1711)
        * Pyupgrade + flynt + f-strings (#1759)
        * Remove unused aggregation subclasses in RediSearch (#1754)
        * Adding RedisCluster client to support Redis Cluster Mode
          (#1660)
        * Support RediSearch FT.PROFILE command (#1727)
        * Adding support for non-decodable commands (#1731)
        * COMMAND GETKEYS support (#1738)
        * RedisJSON 2.0.4 behaviour support (#1747)
        * Removing deprecating distutils (PEP 632) (#1730)
        * Updating PR template (#1745)
        * Removing duplication of Script class (#1751)
        * Splitting documentation for read the docs (#1743)
        * Improve code coverage for aggregation tests (#1713)
        * Fixing COMMAND GETKEYS tests (#1750)
        * GitHub release improvements (#1684)
    - Release 4.0.2
        * Restoring Sentinel commands to redis client (#1723)
        * Better removal of hiredis warning (#1726)
        * Adding links to redis documents in function calls (#1719)
    - Release 4.0.1
        * Removing command on initial connections (#1722)
        * Removing hiredis warning when not installed (#1721)
    - Release 4.0.0
        * FT.EXPLAINCLI intentionally raising NotImplementedError
        * Restoring ZRANGE desc for Redis < 6.2.0 (#1697)
        * Response parsing occasionally fails to parse floats (#1692)
        * Re-enabling read-the-docs (#1707)
        * Call HSET after FT.CREATE to avoid keyspace scan (#1706)
        * Unit tests fixes for compatibility (#1703)
        * Improve documentation about Locks (#1701)
        * Fixes to allow --redis-url to pass through all tests (#1700)
        * Fix unit tests running against Redis 4.0.0 (#1699)
        * Search alias test fix (#1695)
        * Adding RediSearch/RedisJSON tests (#1691)
        * Updating codecov rules (#1689)
        * Tests to validate custom JSON decoders (#1681)
        * Added breaking icon to release drafter (#1702)
        * Removing dependency on six (#1676)
        * Re-enable pipeline support for JSON and TimeSeries (#1674)
        * Export Sentinel, and SSL like other classes (#1671)
        * Restore zrange functionality for older versions of Redis
          (#1670)
        * Fixed garbage collection deadlock (#1578)
        * Tests to validate built python packages (#1678)
        * Sleep for flaky search test (#1680)
        * Test function renames, to match standards (#1679)
        * Docstring improvements for Redis class (#1675)
        * Fix georadius tests (#1672)
        * Improvements to JSON coverage (#1666)
        * Add python_requires setuptools check for python > 3.6 (#1656)
        * SMISMEMBER support (#1667)
        * Exposing the module version in loaded_modules (#1648)
        * RedisTimeSeries support (#1652)
        * Support for json multipath ($) (#1663)
        * Added boolean parsing to PEXPIRE and PEXPIREAT (#1665)
        * Add python_requires setuptools check for python > 3.6 (#1656)
        * Adding vulture for static analysis (#1655)
        * Starting to clean the docs (#1657)
        * Update README.md (#1654)
        * Adding description format for package (#1651)
        * Publish to pypi as releases are generated with the release
          drafter (#1647)
        * Restore actions to prs (#1653)
        * Fixing the package to include commands (#1649)
        * Re-enabling codecov as part of CI process (#1646)
        * Adding support for redisearch (#1640) Thanks @chayim
        * redisjson support (#1636) Thanks @chayim
        * Sentinel: Add SentinelManagedSSLConnection (#1419) Thanks
          @AbdealiJK
        * Enable floating parameters in SET (ex and px) (#1635) Thanks
          @AvitalFineRedis
        * Add warning when hiredis not installed. Recommend
          installation. (#1621) Thanks @adiamzn
        * Raising NotImplementedError for SCRIPT DEBUG and DEBUG
          SEGFAULT (#1624) Thanks @chayim
        * CLIENT REDIR command support (#1623) Thanks @chayim
        * REPLICAOF command implementation (#1622) Thanks @chayim
        * Add support to NX XX and CH to GEOADD (#1605) Thanks
          @AvitalFineRedis
        * Add support to ZRANGE and ZRANGESTORE parameters (#1603)
          Thanks @AvitalFineRedis
        * Pre 6.2 redis should default to None for script flush (#1641)
          Thanks @chayim
        * Add FULL option to XINFO SUMMARY (#1638) Thanks @agusdmb
        * Geosearch test should use any=True (#1594) Thanks
          @Andrew-Chen-Wang
        * Removing packaging dependency (#1626) Thanks @chayim
        * Fix client_kill_filter docs for skimpy (#1596) Thanks
          @Andrew-Chen-Wang
        * Normalize minid and maxlen docs (#1593) Thanks
          @Andrew-Chen-Wang
        * Update docs for multiple usernames for ACL DELUSER (#1595)
          Thanks @Andrew-Chen-Wang
        * Fix grammar of get param in set command (#1588) Thanks
          @Andrew-Chen-Wang
        * Fix docs for client_kill_filter (#1584) Thanks
          @Andrew-Chen-Wang
        * Convert README & CONTRIBUTING from rst to md (#1633) Thanks
          @davidylee
        * Test BYLEX param in zrangestore (#1634) Thanks
          @AvitalFineRedis
        * Tox integrations with invoke and docker (#1632) Thanks
          @chayim
        * Adding the release drafter to help simplify release notes
          (#1618). Thanks @chayim
        * BACKWARDS INCOMPATIBLE: Removed support for end of life
          Python 2.7. #1318
        * BACKWARDS INCOMPATIBLE: All values within Redis URLs are
          unquoted via urllib.parse.unquote. Prior versions of redis-py
          supported this by specifying the ``decode_components`` flag
          to the ``from_url`` functions. This is now done by default
          and cannot be disabled. #589
        * POTENTIALLY INCOMPATIBLE: Redis commands were moved into a
          mixin (see commands.py). Anyone importing ``redis.client`` to
          access commands directly should import ``redis.commands``.
          #1534, #1550
        * Removed technical debt on REDIS_6_VERSION placeholder. Thanks
          @chayim #1582.
        * Various docus fixes. Thanks @Andrew-Chen-Wang #1585, #1586.
        * Support for LOLWUT command, available since Redis 5.0.0.
          Thanks @brainix #1568.
        * Added support for CLIENT REPLY, available in Redis 3.2.0.
          Thanks @chayim #1581.
        * Support for Auto-reconnect PubSub on get_message. Thanks
          @luhn #1574.
        * Fix RST syntax error in README/ Thanks @JanCBrammer #1451.
        * IDLETIME and FREQ support for RESTORE. Thanks @chayim #1580.
        * Supporting args with MODULE LOAD. Thanks @chayim #1579.
        * Updating RedisLabs with Redis. Thanks @gkorland #1575.
        * Added support for ASYNC to SCRIPT FLUSH available in Redis
          6.2.0. Thanks @chayim. #1567
        * Added CLIENT LIST fix to support multiple client ids
          available in Redis 2.8.12. Thanks @chayim #1563.
        * Added DISCARD support for pipelines available in Redis 2.0.0.
          Thanks @chayim #1565.
        * Added ACL DELUSER support for deleting lists of users
          available in Redis 6.2.0. Thanks @chayim. #1562
        * Added CLIENT TRACKINFO support available in Redis 6.2.0.
          Thanks @chayim. #1560
        * Added GEOSEARCH and GEOSEARCHSTORE support available in Redis
          6.2.0. Thanks @AvitalFine Redis. #1526
        * Added LPUSHX support for lists available in Redis 4.0.0.
          Thanks @chayim. #1559
        * Added support for QUIT available in Redis 1.0.0. Thanks
          @chayim. #1558
        * Added support for COMMAND COUNT available in Redis 2.8.13.
          Thanks @chayim. #1554.
        * Added CREATECONSUMER support for XGROUP available in Redis
          6.2.0. Thanks @AvitalFineRedis. #1553
        * Including slowly complexity in INFO if available. Thanks
          @ian28223 #1489.
        * Added support for STRALGO available in Redis 6.0.0. Thanks
          @AvitalFineRedis. #1528
        * Addes support for ZMSCORE available in Redis 6.2.0. Thanks
          @2014BDuck and @jiekun.zhu. #1437
        * Support MINID and LIMIT on XADD available in Redis 6.2.0.
          Thanks @AvitalFineRedis. #1548
        * Added sentinel commands FLUSHCONFIG, CKQUORUM, FAILOVER, and
          RESET available in Redis 2.8.12. Thanks @otherpirate. #834
        * Migrated Version instead of StrictVersion for Python 3.10.
          Thanks @tirkarthi. #1552
        * Added retry mechanism with backoff. Thanks @nbraun-amazon.
          #1494
        * Migrated commands to a mixin. Thanks @chayim. #1534
        * Added support for ZUNION, available in Redis 6.2.0. Thanks
          @AvitalFineRedis. #1522
        * Added support for CLIENT LIST with ID, available in Redis
          6.2.0. Thanks @chayim. #1505
        * Added support for MINID and LIMIT with xtrim, available in
          Reds 6.2.0. Thanks @chayim. #1508
        * Implemented LMOVE and BLMOVE commands, available in Redis
          6.2.0. Thanks @chayim. #1504
        * Added GET argument to SET command, available in Redis 6.2.0.
          Thanks @2014BDuck. #1412
        * Documentation fixes. Thanks @enjoy-binbin @jonher937. #1496
          #1532
        * Added support for XAUTOCLAIM, available in Redis 6.2.0.
          Thanks @AvitalFineRedis. #1529
        * Added IDLE support for XPENDING, available in Redis 6.2.0.
          Thanks @AvitalFineRedis. #1523
        * Add a count parameter to lpop/rpop, available in Redis 6.2.0.
          Thanks @wavenator. #1487
        * Added a (pypy) trove classifier for Python 3.9. Thanks @D3X.
          #1535
        * Added ZINTER support, available in Redis 6.2.0. Thanks
          @AvitalFineRedis. #1520
        * Added ZINTER support, available in Redis 6.2.0. Thanks
          @AvitalFineRedis. #1520
        * Added ZDIFF and ZDIFFSTORE support, available in Redis 6.2.0.
          Thanks @AvitalFineRedis. #1518
        * Added ZRANGESTORE support, available in Redis 6.2.0. Thanks
          @AvitalFineRedis. #1521
        * Added LT and GT support for ZADD, available in Redis 6.2.0.
          Thanks @chayim. #1509
        * Added ZRANDMEMBER support, available in Redis 6.2.0. Thanks
          @AvitalFineRedis. #1519
        * Added GETDEL support, available in Redis 6.2.0. Thanks
          @AvitalFineRedis. #1514
        * Added CLIENT KILL laddr filter, available in Redis 6.2.0.
          Thanks @chayim. #1506
        * Added CLIENT UNPAUSE, available in Redis 6.2.0. Thanks
          @chayim. #1512
        * Added NOMKSTREAM support for XADD, available in Redis 6.2.0.
          Thanks @chayim. #1507
        * Added HRANDFIELD support, available in Redis 6.2.0. Thanks
          @AvitalFineRedis. #1513
        * Added CLIENT INFO support, available in Redis 6.2.0. Thanks
          @AvitalFineRedis. #1517
        * Added GETEX support, available in Redis 6.2.0. Thanks
          @AvitalFineRedis. #1515
        * Added support for COPY command, available in Redis 6.2.0.
          Thanks @malinaa96. #1492
        * Provide a development and testing environment via docker.
          Thanks @abrookins. #1365
        * Added support for the LPOS command available in Redis 6.0.6.
          Thanks @aparcar #1353/#1354
        * Added support for the ACL LOG command available in Redis 6.
          Thanks @2014BDuck. #1307
        * Added support for ABSTTL option of the RESTORE command
          available in Redis 5.0. Thanks @charettes. #1423
    - Drop account-defaults-redis.patch merged upstream

    - Add account-defaults-redis.patch which fixes failing tests by
      taking into consideration redis defaults, not overwriting them
      (gh#andymccurdy/redis-py#1499).

    - Skipp two tests because of gh#andymccurdy/redis-py#1459.

    - update to 3.5.3
      * Restore try/except clauses to __del__ methods. These will be removed
        in 4.0 when more explicit resource management if enforced. #1339
      * Update the master_address when Sentinels promote a new master. #847
      * Update SentinelConnectionPool to not forcefully disconnect other in-use
        connections which can negatively affect threaded applications. #1345
      3.5.2
      * Tune the locking in ConnectionPool.get_connection so that the lock is
        not held while waiting for the socket to establish and validate the
        TCP connection.
      3.5.1
      * Fix for HSET argument validation to allow any non-None key. Thanks
        @AleksMat, #1337, #1341
      3.5.0
      * Removed exception trapping from __del__ methods. redis-py objects that
        hold various resources implement __del__ cleanup methods to release
        those resources when the object goes out of scope. This provides a
        fallback for when these objects aren't explicitly closed by user code.
        Prior to this change any errors encountered in closing these resources
        would be hidden from the user. Thanks @jdufresne. #1281
      * Expanded support for connection strings specifying a username connecting
        to pre-v6 servers. #1274
      * Optimized Lock's blocking_timeout and sleep. If the lock cannot be
        acquired and the sleep value would cause the loop to sleep beyond
        blocking_timeout, fail immediately. Thanks @clslgrnc. #1263
      * Added support for passing Python memoryviews to Redis command args that
        expect strings or bytes. The memoryview instance is sent directly to
        the socket such that there are zero copies made of the underlying data
        during command packing. Thanks @Cody-G. #1265, #1285
      * HSET command now can accept multiple pairs. HMSET has been marked as
        deprecated now. Thanks to @laixintao #1271
      * Don't manually DISCARD when encountering an ExecAbortError.
        Thanks @nickgaya, #1300/#1301
      * Reset the watched state of pipelines after calling exec. This saves
        a roundtrip to the server by not having to call UNWATCH within
        Pipeline.reset(). Thanks @nickgaya, #1299/#1302
      * Added the KEEPTTL option for the SET command. Thanks
        @laixintao #1304/#1280
      * Added the MEMORY STATS command. #1268
      * Lock.extend() now has a new option, `replace_ttl`. When False (the
        default), Lock.extend() adds the `additional_time` to the lock's existing
        TTL. When replace_ttl=True, the lock's existing TTL is replaced with
        the value of `additional_time`.
      * Add testing and support for PyPy.

    - downgrade requires for redis to recommends

      * Better error handling
    Changes in python-retrying:
    - Switch package to modern Python Stack on SLE-15
      + Add %{?sle15_python_module_pythons}

    - require setuptools

    - Switch to pyproject macros.
    - Stop using greedy globs in %files.

    - Update to version 1.3.4
      * Added Greg Roodt as maintainer
      * Formatted code with black
      * Updated repository references

    - Improve summary.

    - Remove superfluous devel dependency for noarch package

    - Initial package
    Changes in python-semver:
    - update to 3.0.2:
      * :pr:`418`: Replace :class:`~collection.OrderedDict` with
        :class:`dict`.
      * The dict datatype is ordered since Python 3.7. As we do not
        support Python 3.6 anymore, it can be considered safe to avoid
        :class:`~collection.OrderedDict`.
      * :pr:`431`: Clarify version policy for the different semver
        versions (v2, v3, >v3) and the supported Python versions.
      * :gh:`432`: Improve external doc links to Python and Pydantic.
      * :pr:`417`: Amend GitHub Actions to check against MacOS.

    - remove obsolete setup-remove-asterisk.patch
    - update to version 3.0.1:
     - Remove incorrect dependencies from build-system section of pyproject.toml by @mgorny in #405
     - correct typo in function description of next_version by @treee111 in #406
     - Improve GitHub Action by @tomschr in #408
     - Add CITATION.cff for citation by @tomschr in #409
     - Add Version class to __all__ export. Fix #410 by @Soneji in #411
     - Configure docformatter by @tomschr in #412
     - Prepare version 3.0.1 by @tomschr in #413

    - update to version 3.0.0:
     - Bugfixes
      - :gh:`291`: Disallow negative numbers in VersionInfo arguments
        for ``major``, ``minor``, and ``patch``.
      * :gh:`310`: Rework API documentation.
        Follow a more 'semi-manual' attempt and add auto directives
        into :file:`docs/api.rst`.
      * :gh:`344`: Allow empty string, a string with a prefix, or ``None``
        as token in
        :meth:`~semver.version.Version.bump_build` and
        :meth:`~semver.version.Version.bump_prerelease`.
      * :pr:`384`: General cleanup, reformat files:
        * Reformat source code with black again as some config options
          did accidentely exclude the semver source code.
          Mostly remove some includes/excludes in the black config.
        * Integrate concurrency in GH Action
        * Ignore Python files on project dirs in .gitignore
        * Remove unused patterns in MANIFEST.in
        * Use ``extend-exclude`` for flake in :file:`setup.cfg`` and adapt list.
        * Use ``skip_install=True`` in :file:`tox.ini` for black
      * :pr:`393`: Fix command :command:`python -m semver` to avoid the error 'invalid choice'
      * :pr:`396`: Calling :meth:`~semver.version.Version.parse` on a derived class will show correct type of
    derived class.
     - Deprecations
      * :gh:`169`: Deprecate CLI functions not imported from ``semver.cli``.
      * :gh:`234`: In :file:`setup.py` simplified file and remove
        ``Tox`` and ``Clean`` classes
      * :gh:`284`: Deprecate the use of :meth:`~Version.isvalid`.
        Rename :meth:`~semver.version.Version.isvalid`
        to :meth:`~semver.version.Version.is_valid`
        for consistency reasons with :meth:`~semver.version.Version.is_compatible`.
      * :pr:`402`: Keep :func:`semver.compare <semver._deprecated.compare>`.
         Although it breaks consistency with module level functions, it seems it's
         a much needed/used function. It's still unclear if we should deprecate
         this function or not (that's why we use :py:exc:`PendingDeprecationWarning`).
         As we don't have a uniform initializer yet, this function stays in the
         :file:`_deprecated.py` file for the time being until we find a better solution. See :gh:`258` for
    details.
     - Features
      * Remove :file:`semver.py`
      * Create :file:`src/semver/__init__.py`
      * Create :file:`src/semver/cli.py` for all CLI methods
      * Create :file:`src/semver/_deprecated.py` for the ``deprecated`` decorator and other deprecated
    functions
      * Create :file:`src/semver/__main__.py` to allow calling the CLI using :command:`python -m semver`
      * Create :file:`src/semver/_types.py` to hold type aliases
      * Create :file:`src/semver/version.py` to hold the :class:`Version` class (old name
    :class:`VersionInfo`) and its utility functions
      * Create :file:`src/semver/__about__.py` for all the metadata variables
      * :gh:`213`: Add typing information
      * :gh:`284`: Implement :meth:`~semver.version.Version.is_compatible` to make 'is self compatible with
    X'.
      * :gh:`305`: Rename :class:`~semver.version.VersionInfo` to :class:`~semver.version.Version` but keep an
    alias for compatibility

    - add setup-remove-asterisk.patch to fix build error
    - update to version 3.0.0-dev.4:
     - Bug Fixes:
     - :gh:`374`: Correct Towncrier's config entries in the :file:`pyproject.toml` file.
       The old entries ``[[tool.towncrier.type]]`` are deprecated and need
       to be replaced by ``[tool.towncrier.fragment.<TYPE>]``.
     - Deprecations:
     - :gh:`372`: Deprecate support for Python 3.6.
       Python 3.6 reached its end of life and isn't supported anymore.
       At the time of writing (Dec 2022), the lowest version is 3.7.
       Although the `poll <https://github.com/python-semver/python-semver/discussions/371>`_
       didn't cast many votes, the majority agree to remove support for
       Python 3.6.
     - Improved Documentation:
     - :gh:`335`: Add new section 'Converting versions between PyPI and semver' the limitations
       and possible use cases to convert from one into the other versioning scheme.
     - :gh:`340`: Describe how to get version from a file
     - :gh:`343`: Describe combining Pydantic with semver in the 'Advanced topic'
       section.
     - :gh:`350`: Restructure usage section. Create subdirectory 'usage/' and splitted
       all section into different files.
     - :gh:`351`: Introduce new topics for:
       * 'Migration to semver3'
       * 'Advanced topics'
     - Features:
     - :pr:`359`: Add optional parameter ``optional_minor_and_patch`` in :meth:`.Version.parse`  to allow
    optional
       minor and patch parts.
     - :pr:`362`: Make :meth:`.Version.match` accept a bare version string as match expression, defaulting to
       equality testing.
     - :gh:`364`: Enhance :file:`pyproject.toml` to make it possible to use the
       :command:`pyproject-build` command from the build module.
       For more information, see :ref:`build-semver`.
     - :gh:`365`: Improve :file:`pyproject.toml`.
       * Use setuptools, add metadata. Taken approach from
         `A Practical Guide to Setuptools and Pyproject.toml
         <https://godatadriven.com/blog/a-practical-guide-to-setuptools-and-pyproject-toml/>`_.
       * Doc: Describe building of semver
       * Remove :file:`.travis.yml` in :file:`MANIFEST.in`
         (not needed anymore)
       * Distinguish between Python 3.6 and others in :file:`tox.ini`
       * Add skip_missing_interpreters option for :file:`tox.ini`
       * GH Action: Upgrade setuptools and setuptools-scm and test
         against 3.11.0-rc.2
     - Trivial/Internal Changes:
     - :gh:`378`: Fix some typos in Towncrier configuration

    - switch to the tagged version rather than a gh branch tarball

    - fix support for Python 3.10 with update to development version:
    - update to revision g4d2df08:
     - Changes for the upcoming release can be found in:
     - the `'changelog.d' directory <https://github.com/python-semver/python-
    semver/tree/master/changelog.d>`_:
     - in our repository.:
    - update to version 3.0.0-dev.2:
     - Deprecations:
     - :gh:`169`: Deprecate CLI functions not imported from ``semver.cli``.
     - Features:
     - :gh:`169`: Create semver package and split code among different modules in the packages.
       * Remove :file:`semver.py`
       * Create :file:`src/semver/__init__.py`
       * Create :file:`src/semver/cli.py` for all CLI methods
       * Create :file:`src/semver/_deprecated.py` for the ``deprecated`` decorator and other deprecated
    functions
       * Create :file:`src/semver/__main__.py` to allow calling the CLI using :command:`python -m semver`
       * Create :file:`src/semver/_types.py` to hold type aliases
       * Create :file:`src/semver/version.py` to hold the :class:`Version` class (old name
    :class:`VersionInfo`) and its utility functions
       * Create :file:`src/semver/__about__.py` for all the metadata variables
     - :gh:`305`: Rename :class:`VersionInfo` to :class:`Version` but keep an alias for compatibility
     - Improved Documentation:
     - :gh:`304`: Several improvements in documentation:
       * Reorganize API documentation.
       * Add migration chapter from semver2 to semver3.
       * Distinguish between changlog for version 2 and 3
     - :gh:`305`: Add note about :class:`Version` rename.
     - Trivial/Internal Changes:
     - :gh:`169`: Adapted infrastructure code to the new project layout.
       * Replace :file:`setup.py` with :file:`setup.cfg` because the :file:`setup.cfg` is easier to use
       * Adapt documentation code snippets where needed
       * Adapt tests
       * Changed the ``deprecated`` to hardcode the ``semver`` package name in the warning.
       Increase coverage to 100% for all non-deprecated APIs
     - :gh:`304`: Support PEP-561 :file:`py.typed`.
       According to the mentioned PEP:
         'Package maintainers who wish to support type checking
         of their code MUST add a marker file named :file:`py.typed`
         to their package supporting typing.'
       Add package_data to :file:`setup.cfg` to include this marker in dist
       and whl file.
    - update to version 3.0.0-dev.1:
     - Deprecations:
     - :pr:`290`: For semver 3.0.0-alpha0:
       * Remove anything related to Python2
       * In :file:`tox.ini` and :file:`.travis.yml`
         Remove targets py27, py34, py35, and pypy.
         Add py38, py39, and nightly (allow to fail)
       * In :file:`setup.py` simplified file and remove
         ``Tox`` and ``Clean`` classes
       * Remove old Python versions (2.7, 3.4, 3.5, and pypy)
         from Travis
     - :gh:`234`: In :file:`setup.py` simplified file and remove
       ``Tox`` and ``Clean`` classes
     - Features:
     - :pr:`290`: Create semver 3.0.0-alpha0
       * Update :file:`README.rst`, mention maintenance
         branch ``maint/v2``.
       * Remove old code mainly used for Python2 compatibility,
         adjusted code to support Python3 features.
       * Split test suite into separate files under :file:`tests/`
         directory
       * Adjust and update :file:`setup.py`. Requires Python >=3.6.*
         Extract metadata directly from source (affects all the ``__version__``,
         ``__author__`` etc. variables)
     - :gh:`270`: Configure Towncrier (:pr:`273`:)
       * Add :file:`changelog.d/.gitignore` to keep this directory
       * Create :file:`changelog.d/README.rst` with some descriptions
       * Add :file:`changelog.d/_template.rst` as Towncrier template
       * Add ``[tool.towncrier]`` section in :file:`pyproject.toml`
       * Add 'changelog' target into :file:`tox.ini`. Use it like
         :command:`tox -e changelog -- CMD` whereas ``CMD`` is a
         Towncrier command. The default :command:`tox -e changelog`
         calls Towncrier to create a draft of the changelog file
         and output it to stdout.
       * Update documentation and add include a new section
         'Changelog' included from :file:`changelog.d/README.rst`.
     - :gh:`276`: Document how to create a sublass from :class:`VersionInfo` class
     - :gh:`213`: Add typing information
     - Bug Fixes:
     - :gh:`291`: Disallow negative numbers in VersionInfo arguments
       for ``major``, ``minor``, and ``patch``.
     - Improved Documentation:
     - :pr:`290`: Several improvements in the documentation:
       * New layout to distinguish from the semver2 development line.
       * Create new logo.
       * Remove any occurances of Python2.
       * Describe changelog process with Towncrier.
       * Update the release process.
     - Trivial/Internal Changes:
     - :pr:`290`: Add supported Python versions to :command:`black`.
     * PR #62. Support custom default names for pre and build
    Changes in python-sshtunnel:
    - Require update-alternatives for the scriptlets.

    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - Use %sle15_python_module_pythons

    - do not require python-mock for build

    - update to 0.4.0:
        + Change the daemon mod flag for all tunnel threads (is not fully backward
          compatible) to prevent unexpected hangs (`#219`_) + Add docker based end to end
          functinal tests for Mongo/Postgres/MySQL
        + Add docker based end to end hangs tests
        + Fix host key directory detection
        + Unify default ssh config folder to `~/.ssh`
        + Increase open connection timeout to 10 secods
        + Change default with context behavior to use `.stop(force=True)` on exit
        + Remove useless `daemon_forward_servers = True` hack for hangs prevention
        + Set transport keepalive to 5 second by default
        + Set default transport timeout to 0.1
        + Deprecate and remove `block_on_close` option
        + Fix 'deadlocks' / 'tunneling hangs'
        + Add `.stop(force=True)` for force close active connections
        + Fixes bug with orphan thread for a tunnel that is DOWN
        + Support IPv6 without proxy command. Use built-in paramiko create socket
          logic. The logic tries to use ipv6 socket family first, then ipv4 socket
          family.

    Changes in python-strictyaml:

    - require setuptools

    - update to 1.7.3:
      * REFACTOR : Fix pipeline.
      * TOOLING : Improvements to pyenv multi-environment tester.
      * FEATURE : Upgraded package to use pyproject.toml files
      * REFACTOR : Fixed linter errors.
      * TOOLING : Build wheel and sdist that both work.

    - Add %{?sle15_python_module_pythons}

    - Update to 1.6.2
      No relevant code changes.
      see details changelog: https://hitchdev.com/strictyaml/changelog/#latest

    - update to 1.6.1
      too many changes to be listed here
      see detailed changelog: https://hitchdev.com/strictyaml/changelog/

    - update to 1.4.4
      * Add support for NaN and infinity representations
      * Optional keys in mappings and set value to None
      * Support underscores in int and decimal
      * NullNone - parse 'null' as None like YAML 1.2 does.
      * Bundle last propertly working ruamel.yaml version in with strictyaml.

    - version update to 1.0.6
      * BUGFIX : Fix accidental python 2 breakage.
      * BUGFIX : Accidental misrecognition of boolean values as numbers - cause of #85.
      * BUGFIX : Fix for #86 - handle changing multiline strings.
      * BUGFIX: handle deprecated collections import in the parser (#82)

    - Update to 1.0.5:
      * BUGFIX : Fixed python 2 bug introduced when fixing #72.
      * FEATURE : Include tests / stories in package.
      * BUG: issue #72. Now setitem uses schema.

    - Expand %description.

    - Initial spec for v1.0.3
    Changes in python-sure:
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install

    - update to 2.0.1:
      * Fixes CI build (Github Actions)
      * Fixes broken tests
      * Housekeeping: Licensing
      * Disable nosetests for testing leaving only pytest as
        supported test-runner for now

    - Add %{?sle15_python_module_pythons}

    - Remove mock from BuildRequires.
    - Rebase python-sure-no-mock.patch to remove one missed import.

    - do not require mock for build nor runtime
    - added patches
      fix https://github.com/gabrielfalcao/sure/pull/161
      + python-sure-no-mock.patch

    - Update to 2.0.0
      * No longer patch the builtin dir() function, which fixes pytest
        in some cases such as projects using gevent.

    - switch to pytest

    - Version update to 1.4.11:
      * Reading the version dynamically was causing import errors that caused error when installing package.
    Refs #144

    Changes in python-vcrpy:
    - Update to 6.0.1
      * BREAKING: Fix issue with httpx support (thanks @parkerhancock) in #784.
      * BREAKING: Drop support for `boto` (vcrpy still supports boto3, but is dropping the deprecated `boto`
    support in this release. (thanks @jairhenrique)
      * Fix compatibility issue with Python 3.12 (thanks @hartwork)
      * Drop simplejson (fixes some compatibility issues) (thanks @jairhenrique)
      * Run CI on Python 3.12 and PyPy 3.9-3.10 (thanks @mgorny)
      * Various linting and docs improvements (thanks @jairhenrique)
      * Tornado fixes (thanks @graingert)

    - version update to 5.1.0
      * Use ruff for linting (instead of current flake8/isort/pyflakes) - thanks @jairhenrique
      * Enable rule B (flake8-bugbear) on ruff - thanks @jairhenrique
      * Configure read the docs V2 - thanks @jairhenrique
      * Fix typo in docs - thanks @quasimik
      * Make json.loads of Python >=3.6 decode bytes by itself - thanks @hartwork
      * Fix body matcher for chunked requests (fixes #734) - thanks @hartwork
      * Fix query param filter for aiohttp (fixes #517) - thanks @hartwork and @salomvary
      * Remove unnecessary dependency on six. - thanks @charettes
      * build(deps): update sphinx requirement from <7 to <8 - thanks @jairhenrique
      * Add action to validate docs - thanks @jairhenrique
      * Add editorconfig file - thanks @jairhenrique
      * Drop iscoroutinefunction fallback function for unsupported python thanks @jairhenrique
    - for changelog for older releases refer to https://github.com/kevin1024/vcrpy/releases
    - six is not required

    - Use sle15_python_module_pythons

    - Restrict urllib3 < 2 -- gh#kevin1024/vcrpy#688

    - Update to version 4.2.1
      * Fix a bug where the first request in a redirect chain was not being recorded with aiohttp
      * Various typos and small fixes, thanks @jairhenrique, @timgates42

    - Update to 4.1.1:
      * Fix HTTPX support for versions greater than 0.15 (thanks @jairhenrique)
      * Include a trailing newline on json cassettes (thanks @AaronRobson)

    - Update to 4.1.0:
      * Add support for httpx!! (thanks @herdigiorgi)
      * Add the new allow_playback_repeats option (thanks @tysonholub)
      * Several aiohttp improvements (cookie support, multiple headers with same
        key) (Thanks @pauloromeira)
      * Use enums for record modes (thanks @aaronbannin)
      * Bugfix: Do not redirect on 304 in aiohttp (Thanks @royjs)
      * Bugfix: Fix test suite by switching to mockbin (thanks @jairhenrique)

    - Remove patch 0001-Revert-v4.0.x-Remove-legacy-python-and-add-python3.8.patch
      as we dropped py2 integration support on Tumbleweed

    - Added patch 0001-Revert-v4.0.x-Remove-legacy-python-and-add-python3.8.patch
      * Enable python2 again since it breaks many packages
    - Fix locale on Leap

    - update to version 4.0.2
      * Remove Python2 support
      * Add Python 3.8 TravisCI support
      * Correct mock imports

    Changes in python-xmltodict:
    - Clean up the SPEC file.

    - add sle15_python_module_pythons

    - update to 0.13.0:
      * Add install info to readme for openSUSE. (#205)
      * Support defaultdict for namespace mapping (#211)
      * parse(generator) is now possible (#212)
      * Processing comments on parsing from xml to dict (connected to #109) (#221)
      * Add expand_iter kw to unparse to expand iterables (#213)
      * Fixed some typos
      * Add support for python3.8
      * Drop Jython/Python 2 and add Python 3.9/3.10.
      * Drop OrderedDict in Python >= 3.7
      * Do not use len() to determine if a sequence is empty
      * Add more namespace attribute tests
      * Fix encoding issue in setup.py

    - Add patch skip-tests-expat-245.patch:
      * Do not run tests that make no sense with a current Expat.

    Changes in python-asgiref:

    First package shipment.

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/761162");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209571");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209811");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209812");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1216606");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222880");
  # https://lists.suse.com/pipermail/sle-security-updates/2024-July/018833.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?065ebaeb");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-28858");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-28859");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-28859");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-paramiko-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-tqdm-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-Automat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-Deprecated");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-Fabric");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-PyGithub");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-PyJWT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-Pygments");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-Twisted");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-Twisted-all_non_platform");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-Twisted-conch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-Twisted-conch_nacl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-Twisted-contextvars");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-Twisted-http2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-Twisted-serial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-Twisted-tls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aiohttp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aiosignal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-antlr4-python3-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-argcomplete");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-asgiref");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-async_timeout");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-avro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-blinker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-chardet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-constantly");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-decorator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-docker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-fixedint");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-fluidity-sm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-frozenlist");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-humanfriendly");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-hyperlink");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-importlib-metadata");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-incremental");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-invoke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-isodate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-javaproperties");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-jsondiff");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-knack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-lexicon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-marshmallow");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-multidict");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-oauthlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-opencensus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-opencensus-context");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-opencensus-ext-threading");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-opentelemetry-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-opentelemetry-sdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-opentelemetry-semantic-conventions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-opentelemetry-test-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-paramiko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-pathspec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-pip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-pkginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-portalocker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-psutil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-pycomposefile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-pydash");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-pyparsing");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-requests-oauthlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-retrying");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-scp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-semver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-service_identity");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-sortedcontainers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-strictyaml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-tabulate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-tqdm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-vcrpy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-websocket-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-wrapt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-yarl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-zope.interface");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES|SUSE)") audit(AUDIT_OS_NOT, "SUSE / openSUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)(?:_SAP)?\d+|SUSE([\d.]+))", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE / openSUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLED15|SLED_SAP15|SLES15|SLES_SAP15|SUSE15\.5|SUSE15\.6)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLED15 / SLED_SAP15 / SLES15 / SLES_SAP15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLED15" && (! preg(pattern:"^(6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED15 SP6", os_ver + " SP" + service_pack);
if (os_ver == "SLED_SAP15" && (! preg(pattern:"^(6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED_SAP15 SP6", os_ver + " SP" + service_pack);
if (os_ver == "SLES15" && (! preg(pattern:"^(6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP6", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP15" && (! preg(pattern:"^(6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP15 SP6", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'python-paramiko-doc-3.4.0-150400.13.10.4', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python-paramiko-doc-3.4.0-150400.13.10.4', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python-tqdm-bash-completion-4.66.1-150400.9.7.4', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python-tqdm-bash-completion-4.66.1-150400.9.7.4', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-Automat-22.10.0-150400.3.7.2', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-Automat-22.10.0-150400.3.7.2', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-Deprecated-1.2.14-150400.10.7.2', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-Deprecated-1.2.14-150400.10.7.2', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-Fabric-3.2.2-150400.10.4.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-PyGithub-1.57-150400.10.4.4', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-PyJWT-2.8.0-150400.8.7.2', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-PyJWT-2.8.0-150400.8.7.2', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-Pygments-2.15.1-150400.7.7.4', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-Pygments-2.15.1-150400.7.7.4', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-Twisted-22.10.0-150400.5.17.4', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-Twisted-22.10.0-150400.5.17.4', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-Twisted-all_non_platform-22.10.0-150400.5.17.4', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-Twisted-all_non_platform-22.10.0-150400.5.17.4', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-Twisted-conch-22.10.0-150400.5.17.4', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-Twisted-conch-22.10.0-150400.5.17.4', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-Twisted-conch_nacl-22.10.0-150400.5.17.4', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-Twisted-conch_nacl-22.10.0-150400.5.17.4', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-Twisted-contextvars-22.10.0-150400.5.17.4', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-Twisted-contextvars-22.10.0-150400.5.17.4', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-Twisted-http2-22.10.0-150400.5.17.4', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-Twisted-http2-22.10.0-150400.5.17.4', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-Twisted-serial-22.10.0-150400.5.17.4', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-Twisted-serial-22.10.0-150400.5.17.4', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-Twisted-tls-22.10.0-150400.5.17.4', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-Twisted-tls-22.10.0-150400.5.17.4', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aiohttp-3.9.3-150400.10.18.4', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aiohttp-3.9.3-150400.10.18.4', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aiosignal-1.3.1-150400.9.7.2', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aiosignal-1.3.1-150400.9.7.2', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-antlr4-python3-runtime-4.13.1-150400.10.4.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-argcomplete-3.3.0-150400.12.12.2', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-argcomplete-3.3.0-150400.12.12.2', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-asgiref-3.6.0-150400.9.7.3', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-async_timeout-4.0.2-150400.10.7.2', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-async_timeout-4.0.2-150400.10.7.2', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-avro-1.11.3-150400.10.4.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-blinker-1.6.2-150400.12.7.4', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-blinker-1.6.2-150400.12.7.4', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-chardet-5.2.0-150400.13.7.2', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-chardet-5.2.0-150400.13.7.2', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-constantly-15.1.0-150400.12.7.2', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-constantly-15.1.0-150400.12.7.2', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-decorator-5.1.1-150400.12.7.4', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-decorator-5.1.1-150400.12.7.4', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-docker-7.0.0-150400.8.4.4', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-fixedint-0.2.0-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-fluidity-sm-0.2.0-150400.10.7.2', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-fluidity-sm-0.2.0-150400.10.7.2', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-frozenlist-1.3.3-150400.9.7.2', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-frozenlist-1.3.3-150400.9.7.2', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-humanfriendly-10.0-150400.13.7.4', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-humanfriendly-10.0-150400.13.7.4', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-hyperlink-21.0.0-150400.12.7.4', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-hyperlink-21.0.0-150400.12.7.4', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-importlib-metadata-6.8.0-150400.10.9.2', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-importlib-metadata-6.8.0-150400.10.9.2', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-incremental-22.10.0-150400.3.7.2', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-incremental-22.10.0-150400.3.7.2', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-invoke-2.1.2-150400.10.7.4', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-invoke-2.1.2-150400.10.7.4', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-isodate-0.6.1-150400.12.7.2', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-isodate-0.6.1-150400.12.7.2', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-javaproperties-0.8.1-150400.10.4.4', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-jsondiff-2.0.0-150400.10.4.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-knack-0.11.0-150400.10.4.4', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-lexicon-2.0.1-150400.10.7.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-lexicon-2.0.1-150400.10.7.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-marshmallow-3.20.2-150400.9.7.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-multidict-6.0.4-150400.7.7.4', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-multidict-6.0.4-150400.7.7.4', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-oauthlib-3.2.2-150400.12.7.4', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-oauthlib-3.2.2-150400.12.7.4', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-opencensus-0.11.4-150400.10.6.3', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-opencensus-context-0.1.3-150400.10.6.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-opencensus-ext-threading-0.1.2-150400.10.6.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-opentelemetry-api-1.23.0-150400.10.7.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-opentelemetry-api-1.23.0-150400.10.7.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-opentelemetry-sdk-1.23.0-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-opentelemetry-semantic-conventions-0.44b0-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-opentelemetry-test-utils-0.44b0-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-paramiko-3.4.0-150400.13.10.4', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-paramiko-3.4.0-150400.13.10.4', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-pathspec-0.11.1-150400.9.7.2', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-pathspec-0.11.1-150400.9.7.2', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-pip-22.3.1-150400.17.16.4', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-pip-22.3.1-150400.17.16.4', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-pkginfo-1.9.6-150400.7.7.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-pkginfo-1.9.6-150400.7.7.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-portalocker-2.7.0-150400.10.7.4', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-portalocker-2.7.0-150400.10.7.4', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-psutil-5.9.5-150400.6.9.4', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-psutil-5.9.5-150400.6.9.4', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-pycomposefile-0.0.30-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-pydash-6.0.2-150400.9.4.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-pyparsing-3.0.9-150400.5.7.4', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-pyparsing-3.0.9-150400.5.7.4', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-requests-oauthlib-1.3.1-150400.12.7.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-requests-oauthlib-1.3.1-150400.12.7.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-retrying-1.3.4-150400.12.4.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-scp-0.14.5-150400.12.7.4', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-scp-0.14.5-150400.12.7.4', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-semver-3.0.2-150400.10.4.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-service_identity-23.1.0-150400.8.7.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-service_identity-23.1.0-150400.8.7.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-sortedcontainers-2.4.0-150400.8.7.4', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-sortedcontainers-2.4.0-150400.8.7.4', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-strictyaml-1.7.3-150400.9.3.4', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-tabulate-0.9.0-150400.11.7.4', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-tabulate-0.9.0-150400.11.7.4', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-tqdm-4.66.1-150400.9.7.4', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-tqdm-4.66.1-150400.9.7.4', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-vcrpy-6.0.1-150400.7.4.4', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-websocket-client-1.5.1-150400.13.7.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-websocket-client-1.5.1-150400.13.7.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-wrapt-1.15.0-150400.12.7.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-wrapt-1.15.0-150400.12.7.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-yarl-1.9.2-150400.8.7.4', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-yarl-1.9.2-150400.8.7.4', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-zope.interface-6.0-150400.12.7.4', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-zope.interface-6.0-150400.12.7.4', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python-paramiko-doc-3.4.0-150400.13.10.4', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python-paramiko-doc-3.4.0-150400.13.10.4', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python-tqdm-bash-completion-4.66.1-150400.9.7.4', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python-tqdm-bash-completion-4.66.1-150400.9.7.4', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-Automat-22.10.0-150400.3.7.2', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-Automat-22.10.0-150400.3.7.2', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-Deprecated-1.2.14-150400.10.7.2', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-Deprecated-1.2.14-150400.10.7.2', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-Fabric-3.2.2-150400.10.4.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-PyGithub-1.57-150400.10.4.4', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-PyJWT-2.8.0-150400.8.7.2', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-PyJWT-2.8.0-150400.8.7.2', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-Pygments-2.15.1-150400.7.7.4', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-Pygments-2.15.1-150400.7.7.4', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-Twisted-22.10.0-150400.5.17.4', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-Twisted-22.10.0-150400.5.17.4', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-Twisted-all_non_platform-22.10.0-150400.5.17.4', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-Twisted-all_non_platform-22.10.0-150400.5.17.4', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-Twisted-conch-22.10.0-150400.5.17.4', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-Twisted-conch-22.10.0-150400.5.17.4', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-Twisted-conch_nacl-22.10.0-150400.5.17.4', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-Twisted-conch_nacl-22.10.0-150400.5.17.4', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-Twisted-contextvars-22.10.0-150400.5.17.4', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-Twisted-contextvars-22.10.0-150400.5.17.4', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-Twisted-http2-22.10.0-150400.5.17.4', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-Twisted-http2-22.10.0-150400.5.17.4', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-Twisted-serial-22.10.0-150400.5.17.4', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-Twisted-serial-22.10.0-150400.5.17.4', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-Twisted-tls-22.10.0-150400.5.17.4', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-Twisted-tls-22.10.0-150400.5.17.4', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aiohttp-3.9.3-150400.10.18.4', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aiohttp-3.9.3-150400.10.18.4', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aiosignal-1.3.1-150400.9.7.2', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aiosignal-1.3.1-150400.9.7.2', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-antlr4-python3-runtime-4.13.1-150400.10.4.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-argcomplete-3.3.0-150400.12.12.2', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-argcomplete-3.3.0-150400.12.12.2', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-asgiref-3.6.0-150400.9.7.3', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-packagehub-subpackages-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-async_timeout-4.0.2-150400.10.7.2', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-async_timeout-4.0.2-150400.10.7.2', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-avro-1.11.3-150400.10.4.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-blinker-1.6.2-150400.12.7.4', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-blinker-1.6.2-150400.12.7.4', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-chardet-5.2.0-150400.13.7.2', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-chardet-5.2.0-150400.13.7.2', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-constantly-15.1.0-150400.12.7.2', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-constantly-15.1.0-150400.12.7.2', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-decorator-5.1.1-150400.12.7.4', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-decorator-5.1.1-150400.12.7.4', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-docker-7.0.0-150400.8.4.4', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-fixedint-0.2.0-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-fluidity-sm-0.2.0-150400.10.7.2', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-fluidity-sm-0.2.0-150400.10.7.2', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-frozenlist-1.3.3-150400.9.7.2', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-frozenlist-1.3.3-150400.9.7.2', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-humanfriendly-10.0-150400.13.7.4', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-humanfriendly-10.0-150400.13.7.4', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-hyperlink-21.0.0-150400.12.7.4', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-hyperlink-21.0.0-150400.12.7.4', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-importlib-metadata-6.8.0-150400.10.9.2', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-importlib-metadata-6.8.0-150400.10.9.2', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-incremental-22.10.0-150400.3.7.2', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-incremental-22.10.0-150400.3.7.2', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-invoke-2.1.2-150400.10.7.4', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-invoke-2.1.2-150400.10.7.4', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-isodate-0.6.1-150400.12.7.2', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-isodate-0.6.1-150400.12.7.2', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-javaproperties-0.8.1-150400.10.4.4', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-jsondiff-2.0.0-150400.10.4.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-knack-0.11.0-150400.10.4.4', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-lexicon-2.0.1-150400.10.7.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-lexicon-2.0.1-150400.10.7.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-marshmallow-3.20.2-150400.9.7.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-multidict-6.0.4-150400.7.7.4', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-multidict-6.0.4-150400.7.7.4', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-oauthlib-3.2.2-150400.12.7.4', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-oauthlib-3.2.2-150400.12.7.4', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-opencensus-0.11.4-150400.10.6.3', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-opencensus-context-0.1.3-150400.10.6.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-opencensus-ext-threading-0.1.2-150400.10.6.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-opentelemetry-api-1.23.0-150400.10.7.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-opentelemetry-api-1.23.0-150400.10.7.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-opentelemetry-sdk-1.23.0-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-opentelemetry-semantic-conventions-0.44b0-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-opentelemetry-test-utils-0.44b0-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-paramiko-3.4.0-150400.13.10.4', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-paramiko-3.4.0-150400.13.10.4', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-pathspec-0.11.1-150400.9.7.2', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-pathspec-0.11.1-150400.9.7.2', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-pip-22.3.1-150400.17.16.4', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-pip-22.3.1-150400.17.16.4', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-pkginfo-1.9.6-150400.7.7.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-pkginfo-1.9.6-150400.7.7.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-portalocker-2.7.0-150400.10.7.4', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-portalocker-2.7.0-150400.10.7.4', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-psutil-5.9.5-150400.6.9.4', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-psutil-5.9.5-150400.6.9.4', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-pycomposefile-0.0.30-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-pydash-6.0.2-150400.9.4.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-pyparsing-3.0.9-150400.5.7.4', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-pyparsing-3.0.9-150400.5.7.4', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-requests-oauthlib-1.3.1-150400.12.7.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-requests-oauthlib-1.3.1-150400.12.7.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-retrying-1.3.4-150400.12.4.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-scp-0.14.5-150400.12.7.4', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-scp-0.14.5-150400.12.7.4', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-semver-3.0.2-150400.10.4.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-service_identity-23.1.0-150400.8.7.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-service_identity-23.1.0-150400.8.7.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-sortedcontainers-2.4.0-150400.8.7.4', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-sortedcontainers-2.4.0-150400.8.7.4', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-strictyaml-1.7.3-150400.9.3.4', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-tabulate-0.9.0-150400.11.7.4', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-tabulate-0.9.0-150400.11.7.4', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-tqdm-4.66.1-150400.9.7.4', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-tqdm-4.66.1-150400.9.7.4', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-vcrpy-6.0.1-150400.7.4.4', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-websocket-client-1.5.1-150400.13.7.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-websocket-client-1.5.1-150400.13.7.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-wrapt-1.15.0-150400.12.7.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-wrapt-1.15.0-150400.12.7.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-yarl-1.9.2-150400.8.7.4', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-yarl-1.9.2-150400.8.7.4', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-zope.interface-6.0-150400.12.7.4', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-zope.interface-6.0-150400.12.7.4', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python-paramiko-doc-3.4.0-150400.13.10.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python-tqdm-bash-completion-4.66.1-150400.9.7.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-Automat-22.10.0-150400.3.7.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-Deprecated-1.2.14-150400.10.7.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-Fabric-3.2.2-150400.10.4.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-PyGithub-1.57-150400.10.4.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-PyJWT-2.8.0-150400.8.7.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-Pygments-2.15.1-150400.7.7.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-Twisted-22.10.0-150400.5.17.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-Twisted-all_non_platform-22.10.0-150400.5.17.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-Twisted-conch-22.10.0-150400.5.17.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-Twisted-conch_nacl-22.10.0-150400.5.17.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-Twisted-contextvars-22.10.0-150400.5.17.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-Twisted-http2-22.10.0-150400.5.17.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-Twisted-serial-22.10.0-150400.5.17.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-Twisted-tls-22.10.0-150400.5.17.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-aiohttp-3.9.3-150400.10.18.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-aiosignal-1.3.1-150400.9.7.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-antlr4-python3-runtime-4.13.1-150400.10.4.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-argcomplete-3.3.0-150400.12.12.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-asgiref-3.6.0-150400.9.7.3', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-async_timeout-4.0.2-150400.10.7.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-avro-1.11.3-150400.10.4.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-blinker-1.6.2-150400.12.7.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-chardet-5.2.0-150400.13.7.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-constantly-15.1.0-150400.12.7.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-decorator-5.1.1-150400.12.7.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-distro-1.9.0-150400.12.4.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-docker-7.0.0-150400.8.4.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-fakeredis-2.21.0-150400.9.3.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-fixedint-0.2.0-150400.9.3.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-fluidity-sm-0.2.0-150400.10.7.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-frozenlist-1.3.3-150400.9.7.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-httplib2-0.22.0-150400.10.4.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-httpretty-1.1.4-150400.11.4.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-humanfriendly-10.0-150400.13.7.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-hyperlink-21.0.0-150400.12.7.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-importlib-metadata-6.8.0-150400.10.9.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-incremental-22.10.0-150400.3.7.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-invoke-2.1.2-150400.10.7.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-isodate-0.6.1-150400.12.7.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-javaproperties-0.8.1-150400.10.4.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-jsondiff-2.0.0-150400.10.4.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-knack-0.11.0-150400.10.4.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-lexicon-2.0.1-150400.10.7.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-marshmallow-3.20.2-150400.9.7.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-multidict-6.0.4-150400.7.7.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-oauthlib-3.2.2-150400.12.7.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-opencensus-0.11.4-150400.10.6.3', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-opencensus-context-0.1.3-150400.10.6.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-opencensus-ext-threading-0.1.2-150400.10.6.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-opentelemetry-api-1.23.0-150400.10.7.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-opentelemetry-sdk-1.23.0-150400.9.3.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-opentelemetry-semantic-conventions-0.44b0-150400.9.3.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-opentelemetry-test-utils-0.44b0-150400.9.3.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-paramiko-3.4.0-150400.13.10.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-pathspec-0.11.1-150400.9.7.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-pip-22.3.1-150400.17.16.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-pkginfo-1.9.6-150400.7.7.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-portalocker-2.7.0-150400.10.7.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-psutil-5.9.5-150400.6.9.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-pycomposefile-0.0.30-150400.9.3.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-pydash-6.0.2-150400.9.4.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-pyparsing-3.0.9-150400.5.7.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-redis-5.0.1-150400.12.4.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-requests-oauthlib-1.3.1-150400.12.7.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-retrying-1.3.4-150400.12.4.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-scp-0.14.5-150400.12.7.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-semver-3.0.2-150400.10.4.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-service_identity-23.1.0-150400.8.7.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-sortedcontainers-2.4.0-150400.8.7.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-sshtunnel-0.4.0-150400.5.4.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-strictyaml-1.7.3-150400.9.3.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-sure-2.0.1-150400.12.4.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-tabulate-0.9.0-150400.11.7.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-tqdm-4.66.1-150400.9.7.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-typing_extensions-4.5.0-150400.3.9.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-vcrpy-6.0.1-150400.7.4.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-websocket-client-1.5.1-150400.13.7.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-wheel-0.40.0-150400.13.7.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-wrapt-1.15.0-150400.12.7.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-xmltodict-0.13.0-150400.12.4.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-yarl-1.9.2-150400.8.7.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-zipp-3.15.0-150400.10.7.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-zope.interface-6.0-150400.12.7.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python-paramiko-doc-3.4.0-150400.13.10.4', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python-tqdm-bash-completion-4.66.1-150400.9.7.4', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-Automat-22.10.0-150400.3.7.2', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-Deprecated-1.2.14-150400.10.7.2', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-Fabric-3.2.2-150400.10.4.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-PyGithub-1.57-150400.10.4.4', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-PyJWT-2.8.0-150400.8.7.2', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-Pygments-2.15.1-150400.7.7.4', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-Twisted-22.10.0-150400.5.17.4', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-Twisted-all_non_platform-22.10.0-150400.5.17.4', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-Twisted-conch-22.10.0-150400.5.17.4', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-Twisted-conch_nacl-22.10.0-150400.5.17.4', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-Twisted-contextvars-22.10.0-150400.5.17.4', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-Twisted-http2-22.10.0-150400.5.17.4', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-Twisted-serial-22.10.0-150400.5.17.4', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-Twisted-tls-22.10.0-150400.5.17.4', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-aiohttp-3.9.3-150400.10.18.4', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-aiosignal-1.3.1-150400.9.7.2', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-antlr4-python3-runtime-4.13.1-150400.10.4.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-argcomplete-3.3.0-150400.12.12.2', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-asgiref-3.6.0-150400.9.7.3', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-async_timeout-4.0.2-150400.10.7.2', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-avro-1.11.3-150400.10.4.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-blinker-1.6.2-150400.12.7.4', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-chardet-5.2.0-150400.13.7.2', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-constantly-15.1.0-150400.12.7.2', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-decorator-5.1.1-150400.12.7.4', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-distro-1.9.0-150400.12.4.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-docker-7.0.0-150400.8.4.4', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-fakeredis-2.21.0-150400.9.3.4', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-fixedint-0.2.0-150400.9.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-fluidity-sm-0.2.0-150400.10.7.2', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-frozenlist-1.3.3-150400.9.7.2', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-httplib2-0.22.0-150400.10.4.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-httpretty-1.1.4-150400.11.4.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-humanfriendly-10.0-150400.13.7.4', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-hyperlink-21.0.0-150400.12.7.4', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-importlib-metadata-6.8.0-150400.10.9.2', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-incremental-22.10.0-150400.3.7.2', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-invoke-2.1.2-150400.10.7.4', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-isodate-0.6.1-150400.12.7.2', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-javaproperties-0.8.1-150400.10.4.4', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-jsondiff-2.0.0-150400.10.4.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-knack-0.11.0-150400.10.4.4', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-lexicon-2.0.1-150400.10.7.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-marshmallow-3.20.2-150400.9.7.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-multidict-6.0.4-150400.7.7.4', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-oauthlib-3.2.2-150400.12.7.4', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-opencensus-0.11.4-150400.10.6.3', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-opencensus-context-0.1.3-150400.10.6.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-opencensus-ext-threading-0.1.2-150400.10.6.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-opentelemetry-api-1.23.0-150400.10.7.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-opentelemetry-sdk-1.23.0-150400.9.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-opentelemetry-semantic-conventions-0.44b0-150400.9.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-opentelemetry-test-utils-0.44b0-150400.9.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-paramiko-3.4.0-150400.13.10.4', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-pathspec-0.11.1-150400.9.7.2', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-pip-22.3.1-150400.17.16.4', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-pkginfo-1.9.6-150400.7.7.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-portalocker-2.7.0-150400.10.7.4', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-psutil-5.9.5-150400.6.9.4', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-pycomposefile-0.0.30-150400.9.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-pydash-6.0.2-150400.9.4.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-pyparsing-3.0.9-150400.5.7.4', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-redis-5.0.1-150400.12.4.4', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-requests-oauthlib-1.3.1-150400.12.7.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-retrying-1.3.4-150400.12.4.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-scp-0.14.5-150400.12.7.4', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-semver-3.0.2-150400.10.4.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-service_identity-23.1.0-150400.8.7.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-sortedcontainers-2.4.0-150400.8.7.4', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-sshtunnel-0.4.0-150400.5.4.4', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-strictyaml-1.7.3-150400.9.3.4', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-tabulate-0.9.0-150400.11.7.4', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-tqdm-4.66.1-150400.9.7.4', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-typing_extensions-4.5.0-150400.3.9.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-vcrpy-6.0.1-150400.7.4.4', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-websocket-client-1.5.1-150400.13.7.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-wheel-0.40.0-150400.13.7.4', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-wrapt-1.15.0-150400.12.7.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-yarl-1.9.2-150400.8.7.4', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-zipp-3.15.0-150400.10.7.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-zope.interface-6.0-150400.12.7.4', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']}
];

var ltss_caveat_required = FALSE;
var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var exists_check = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (exists_check) {
      var check_flag = 0;
      foreach var check (exists_check) {
        if (!rpm_exists(release:_release, rpm:check)) continue;
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'python-paramiko-doc / python-tqdm-bash-completion / etc');
}
