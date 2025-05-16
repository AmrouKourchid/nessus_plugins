#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
# The descriptive text and package checks in this plugin were
# extracted from Fedora Security Advisory FEDORA-2022-4c634ee466
#

include('compat.inc');

if (description)
{
  script_id(211412);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/15");

  script_cve_id(
    "CVE-2021-41164",
    "CVE-2021-41165",
    "CVE-2022-24728",
    "CVE-2022-24729"
  );
  script_xref(name:"FEDORA", value:"2022-4c634ee466");

  script_name(english:"Fedora 37 : ckeditor (2022-4c634ee466)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Fedora 37 host has a package installed that is affected by multiple vulnerabilities as referenced in the
FEDORA-2022-4c634ee466 advisory.

    ## CKEditor 4.20

    New Features:

    * [#5084](https://github.com/ckeditor/ckeditor4/issues/5084): Added the [`config.tabletools_scopedHeaders`
    ](https://ckeditor.com/docs/ckeditor4/latest/api/CKEDITOR_config.html#cfg-tabletools_scopedHeaders)
    configuration option controlling the behaviour of table headers with and without the `[scope]` attribute.
    * [#5219](https://github.com/ckeditor/ckeditor4/issues/5219): Added the [`config.image2_defaultLockRatio`]
    (https://ckeditor.com/docs/ckeditor4/latest/api/CKEDITOR_config.html#cfg-image2_defaultLockRatio)
    configuration option allowing to set the default value of the Lock ratio option in the [Enhanced
    Image](https://ckeditor.com/cke4/addon/image2) dialog.
    * [#2008](https://github.com/ckeditor/ckeditor-dev/pull/2008): Extended the
    [Mentions](https://ckeditor.com/cke4/addon/mentions) and [Emoji](https://ckeditor.com/cke4/addon/emoji)
    plugins with a feature option that adds a space after an accepted autocompletion match. See:
            * [`configDefinition.followingSpace`](https://ckeditor.com/docs/ckeditor4/latest/api/CKEDITOR_plug
    ins_mentions_configDefinition.html#property-followingSpace) option for the mentions plugin, and
            *
    [`config.emoji_followingSpace`](https://ckeditor.com/docs/ckeditor4/latest/api/CKEDITOR_config.html#cfg-
    emoji_followingSpace) option for the emoji plugin.
    * [#5215](https://github.com/ckeditor/ckeditor4/issues/5215): Added the [`config.coreStyles_toggleSubSup`]
    (https://ckeditor.com/docs/ckeditor4/latest/api/CKEDITOR_config.html#cfg-coreStyles_toggleSubSup)
    configuration option which disallows setting the subscript and superscript on the same element
    simultaneously using UI buttons. This option is turned off by default.

    Fixed Issues:

    * [#4889](https://github.com/ckeditor/ckeditor4/issues/4889): Fixed: Incorrect position of the [Table
    Resize](https://ckeditor.com/cke4/addon/tableresize) cursor after scrolling the editor horizontally.
    * [#5319](https://github.com/ckeditor/ckeditor4/issues/5319): Fixed:
    [Autolink](https://ckeditor.com/cke4/addon/autolink)
    [`config.autolink_urlRegex`](https://ckeditor.com/docs/ckeditor4/latest/api/CKEDITOR_config.html#cfg-
    autolink_urlRegex) option produced invalid links when configured directly using the editor instance
    config. Thanks to [Aigars Zeiza](https://github.com/Zuzon)!
    * [#4941](https://github.com/ckeditor/ckeditor4/issues/4941): Fixed: Some entities got wrongly encoded
    when using [`entities_processNumerical =
    true`](https://ckeditor.com/docs/ckeditor4/latest/api/CKEDITOR_config.html#cfg-entities_processNumerical)
    configuration option.
    * [#4931](https://github.com/ckeditor/ckeditor4/issues/4931): Fixed: Selecting the whole editor content
    when there is only a list with an empty element at the end inside and deleting it did not delete all list
    items.


    API changes:

    * [#5122](https://github.com/ckeditor/ckeditor4/issues/5122): Added the ability to provide a list of
    buttons as an array to the
    [`config.removeButtons`](https://ckeditor.com/docs/ckeditor4/latest/api/CKEDITOR_config.html#cfg-
    removeButtons) config variable.
    * [#2008](https://github.com/ckeditor/ckeditor-dev/pull/2008): Added
    [Autocomplete](https://ckeditor.com/cke4/addon/autocomplete) [`followingSpace`](https://ckeditor.com/docs/
    ckeditor4/latest/api/CKEDITOR_plugins_autocomplete_configDefinition.html#property-followingSpace) option
    that finishes an accepted match with a space.

    ## CKEditor 4.19.1

    Fixed Issues:

    * [#5125](https://github.com/ckeditor/ckeditor4/issues/5125): Fixed: Deleting a widget with disabled
    [autoParagraph](https://ckeditor.com/docs/ckeditor4/latest/api/CKEDITOR_config.html#cfg-autoParagraph) by
    the keyboard `backspace` key removes the editor editable area and crashes the editor.
    * [#5135](https://github.com/ckeditor/ckeditor4/issues/5135): Fixed: The [`checkbox.setValue`](https://cke
    ditor.com/docs/ckeditor4/latest/api/CKEDITOR_ui_dialog_checkbox.html#method-setValue) and
    [`radio.setValue`](https://ckeditor.com/docs/ckeditor4/latest/api/CKEDITOR_ui_dialog_radio.html#method-
    setValue) methods are not chainable as stated in the documentation. Thanks to [Jordan
    Bradford](https://github.com/LordPachelbel)!
    * [#5085](https://github.com/ckeditor/ckeditor4/issues/5085): Fixed: The
    [Language](https://ckeditor.com/cke4/addon/language) plugin removes the element marking the text in
    foreign language if said element does not have an information about the text direction.
    * [#4284](https://github.com/ckeditor/ckeditor4/issues/4284): Fixed:
    [Tableselection](https://ckeditor.com/cke4/addon/tableselection) Merging cells with a rowspan throws an
    unexpected error and does not create an undo step.
    * [#5184](https://github.com/ckeditor/ckeditor4/issues/5184): Fixed: The [Editor
    Placeholder](https://ckeditor.com/cke4/addon/wysiwygarea) plugin degrades typing performance.
    * [#5158](https://github.com/ckeditor/ckeditor4/issues/5158): Fixed: [`CKEDITOR.tools#convertToPx()`](http
    s://ckeditor.com/docs/ckeditor4/latest/api/CKEDITOR_tools.html#method-convertToPx) gives invalid results
    if the helper calculator element was deleted from the DOM.
    * [#5234](https://github.com/ckeditor/ckeditor4/issues/5234): Fixed: [Easy
    Image](https://ckeditor.com/cke4/addon/easyimage) doesn't allow to upload images files using toolbar
    button.
    * [#438](https://github.com/ckeditor/ckeditor4/issues/438): Fixed: It is impossible to navigate to the
    [elementspath](https://ckeditor.com/cke4/addon/elementspath) from the
    [toolbar](https://ckeditor.com/cke4/addon/toolbar) by keyboard and vice versa.
    * [#4449](https://github.com/ckeditor/ckeditor4/issues/4449): Fixed: [`dialog.validate#functions`](https:/
    /ckeditor.com/docs/ckeditor4/latest/api/CKEDITOR_dialog_validate.html#method-functions) incorrectly
    composes functions that return an optional error message, like e.g. [`dialog.validate.number`](https://cke
    ditor.com/docs/ckeditor4/latest/api/CKEDITOR_dialog_validate.html#method-number) due to unnecessary return
    type coercion.
    * [#4473](https://github.com/ckeditor/ckeditor4/issues/4473): Fixed: The
    [dialog.validate](https://ckeditor.com/docs/ckeditor4/latest/api/CKEDITOR_dialog_validate.html) method
    does not accept parameter value. The issue originated in [dialog.validate.functions](https://ckeditor.com/
    docs/ckeditor4/latest/api/CKEDITOR_dialog_validate.html#method-functions) method that did not properly
    propagate parameter value to validator. Affected validators:
            *
    [`functions`](https://ckeditor.com/docs/ckeditor4/latest/api/CKEDITOR_dialog_validate.html#method-
    functions)
            * [`equals`](https://ckeditor.com/docs/ckeditor4/latest/api/CKEDITOR_dialog_validate.html#method-
    equals)
            *
    [`notEqual`](https://ckeditor.com/docs/ckeditor4/latest/api/CKEDITOR_dialog_validate.html#method-notEqual)
            *
    [`cssLength`](https://ckeditor.com/docs/ckeditor4/latest/api/CKEDITOR_dialog_validate.html#method-
    cssLength)
            *
    [`htmlLength`](https://ckeditor.com/docs/ckeditor4/latest/api/CKEDITOR_dialog_validate.html#method-
    htmlLength)
            *
    [`inlineStyle`](https://ckeditor.com/docs/ckeditor4/latest/api/CKEDITOR_dialog_validate.html#method-
    inlineStyle)
    * [#5147](https://github.com/ckeditor/ckeditor4/issues/5147): Fixed: The [Accessibility
    Help](https://ckeditor.com/cke4/addon/a11yhelp) dialog does not contain info about focus being moved back
    to the editing area upon leaving dialogs.
    * [#5144](https://github.com/ckeditor/ckeditor4/issues/5144): Fixed: [Menu
    buttons](https://ckeditor.com/cke4/addon/menubutton) and [panel
    buttons](https://ckeditor.com/cke4/addon/panelbutton) incorrectly indicate the open status of their
    associated pop-up menus in the browser's accessibility tree.
    * [#5022](https://github.com/ckeditor/ckeditor4/issues/5022): Fixed: [Find and
    Replace](https://ckeditor.com/cke4/addon/find) does not respond to the `Enter` key.

    API changes:

    * [#5184](https://github.com/ckeditor/ckeditor4/issues/5184): Added the [`config.editorplaceholder_delay`]
    (https://ckeditor.com/docs/ckeditor4/latest/api/CKEDITOR_config.html#cfg-editorplaceholder_delay)
    configuration option allowing to delay placeholder before it is toggled when changing editor content.
    * [#5184](https://github.com/ckeditor/ckeditor4/issues/5184): Added the
    [`CKEDITOR.tools#debounce()`](https://ckeditor.com/docs/ckeditor4/latest/api/CKEDITOR_tools.html#method-
    debounce) function allowing to postpone a passed function execution until the given milliseconds have
    elapsed since the last time it was invoked.

    ## CKEditor 4.19.0

    New features:

    * [#2444](https://github.com/ckeditor/ckeditor4/issues/2444): Togglable toolbar buttons are now exposed as
    toggle buttons in the browser's accessibility tree.
    * [#4641](https://github.com/ckeditor/ckeditor4/issues/4641): Added an option allowing to cancel the
    [Delayed Editor Creation](https://ckeditor.com/docs/ckeditor4/latest/features/delayed_creation.html)
    feature as a function handle for editor creators
    ([`CKEDITOR.replace`](https://ckeditor.com/docs/ckeditor4/latest/api/CKEDITOR.html#method-replace),
    [`CKEDITOR.inline`](https://ckeditor.com/docs/ckeditor4/latest/api/CKEDITOR.html#method-inline),
    [`CKEDITOR.appendTo`](https://ckeditor.com/docs/ckeditor4/latest/api/CKEDITOR.html#method-appendTo)).
    * [#4986](https://github.com/ckeditor/ckeditor4/issues/4986): Added
    [`config.shiftLineBreaks`](https://ckeditor.com/docs/ckeditor4/latest/api/CKEDITOR_config.html#cfg-
    shiftLineBreaks) allowing to preserve inline elements formatting when the `shift`+`enter` keystroke is
    used.
    * [#2445](https://github.com/ckeditor/ckeditor4/issues/2445): Added
    [`config.applicationTitle`](https://ckeditor.com/docs/ckeditor4/latest/api/CKEDITOR_config.html#cfg-
    applicationTitle) configuration option allowing to customize or disable the editor's application region
    label. This option, combined with
    [`config.title`](https://ckeditor.com/docs/ckeditor4/latest/api/CKEDITOR_config.html#cfg-title), gives
    much better control over the editor's labels read by screen readers.

    Fixed Issues:

    * [#4543](https://github.com/ckeditor/ckeditor4/issues/4543): Fixed: Toolbar buttons toggle state is not
    correctly announced by screen readers lacking the information whether the feature is on or off.
    * [#4052](https://github.com/ckeditor/ckeditor4/issues/4052): Fixed: Editor labels are read incorrectly by
    screen readers due to invalid editor control type for the [Iframe Editing
    Area](https://ckeditor.com/cke4/addon/wysiwygarea) editors.
    * [#1904](https://github.com/ckeditor/ckeditor4/issues/1904): Fixed: Screen readers are not announcing the
    read-only editor state.
    * [#4904](https://github.com/ckeditor/ckeditor4/issues/4904): Fixed: Table cell selection and navigation
    with the `tab` key behavior is inconsistent after adding a new row.
    * [#3394](https://github.com/ckeditor/ckeditor4/issues/3394): Fixed: [Enhanced
    image](https://ckeditor.com/cke4/addon/image2) plugin dialog is not supporting URL with query string
    parameters. Thanks to [Simon Urli](https://github.com/surli)!
    * [#5049](https://github.com/ckeditor/ckeditor4/issues/5049): Fixed: The editor fails in strict mode due
    to not following the `use strict` directives in a core editor module.
    * [#5095](https://github.com/ckeditor/ckeditor4/issues/5095): Fixed: The
    [clipboard](https://ckeditor.com/cke4/addon/clipboard) plugin shows notification about unsupported file
    format when the file type is different than `jpg`, `gif`, `png`, not respecting [supported types](https://
    ckeditor.com/docs/ckeditor4/latest/api/CKEDITOR_fileTools_uploadWidgetDefinition.html#property-
    supportedTypes) by the [Upload Widget](https://ckeditor.com/cke4/addon/uploadwidget) plugin.
    * [#4855](https://github.com/ckeditor/ckeditor4/issues/4855): [iOS] Fixed: Focusing toolbar buttons with
    an enabled VoiceOver screen reader moves the browser focus into an editable area and interrupts button
    functionality.

    API changes:

    * [#4641](https://github.com/ckeditor/ckeditor4/issues/4641): The
    [`CKEDITOR.replace`](https://ckeditor.com/docs/ckeditor4/latest/api/CKEDITOR.html#method-replace),
    [`CKEDITOR.inline`](https://ckeditor.com/docs/ckeditor4/latest/api/CKEDITOR.html#method-inline),
    [`CKEDITOR.appendTo`](https://ckeditor.com/docs/ckeditor4/latest/api/CKEDITOR.html#method-appendTo)
    functions are now returning a handle function allowing to cancel the [Delayed Editor
    Creation](https://ckeditor.com/docs/ckeditor4/latest/features/delayed_creation.html) feature.
    * [#5095](https://github.com/ckeditor/ckeditor4/issues/5095): Added the [CKEDITOR.plugins.clipboard.addFil
    eMatcher](https://ckeditor.com/docs/ckeditor4/latest/api/CKEDITOR_plugins_clipboard.html#method-
    addFileMatcher) function allowing to define file formats supported by the
    [clipboard](https://ckeditor.com/cke4/addon/clipboard) plugin. Trying to paste unsupported files will
    result in a notification that a file cannot be dropped or pasted into the editor.
    * [#2445](https://github.com/ckeditor/ckeditor4/issues/2445): Added
    [`config.applicationTitle`](https://ckeditor.com/docs/ckeditor4/latest/api/CKEDITOR_config.html#cfg-
    applicationTitle) alongside [`CKEDITOR.editor#applicationTitle`](https://ckeditor.com/docs/ckeditor4/lates
    t/api/CKEDITOR_editor.html#property-applicationTitle) to allow customizing editor's application region
    label.

    ## CKEditor 4.18.0

    **Security Updates:**

    * Fixed an XSS vulnerability in the core module reported by GitHub Security Lab team member [Kevin
    Backhouse](https://github.com/kevinbackhouse).

            Issue summary: The vulnerability allowed to inject malformed HTML bypassing content sanitization,
    which could result in executing a JavaScript code. See
    [CVE-2022-24728](https://github.com/ckeditor/ckeditor4/security/advisories/GHSA-4fc4-4p5g-6w89) for more
    details.

    * Fixed a Regular expression Denial of Service (ReDoS) vulnerability in dialog plugin discovered by the
    CKEditor 4 team during our regular security audit.

            Issue summary: The vulnerability allowed to abuse a dialog input validator regular expression,
    which could cause a significant performance drop resulting in a browser tab freeze. See
    [CVE-2022-24729](https://github.com/ckeditor/ckeditor4/security/advisories/GHSA-f6rf-9m92-x2hh) for more
    details.

    You can read more details in the relevant security advisory and [contact us](security@cksource.com) if you
    have more questions.

    **An upgrade is highly recommended!**

    **Highlights:**

    [Web Spell Checker](https://webspellchecker.com/) ended support for WebSpellChecker Dialog on December
    31st, 2021. This means the plugin is not supported any longer. Therefore, we decided to deprecate and
    remove the WebSpellChecker Dialog plugin from CKEditor 4 presets.

    We strongly encourage everyone to choose one of the other available spellchecking solutions - [Spell Check
    As You Type (SCAYT)](https://ckeditor.com/cke4/addon/scayt) or
    [WProofreader](https://ckeditor.com/cke4/addon/wproofreader).

    Fixed issues:

    * [#5097](https://github.com/ckeditor/ckeditor4/issues/5097): [Chrome] Fixed: Incorrect conversion of
    points to pixels while using [`CKEDITOR.tools.convertToPx()`](https://ckeditor.com/docs/ckeditor4/latest/a
    pi/CKEDITOR_tools.html#method-convertToPx).
    * [#5044](https://github.com/ckeditor/ckeditor4/issues/5044): Fixed: `select` elements with `multiple`
    attribute had incorrect styling. Thanks to [John R. D'Orazio](https://github.com/JohnRDOrazio)!

    Other changes:

    * [#5093](https://github.com/ckeditor/ckeditor4/issues/5093): Deprecated and removed WebSpellChecker
    Dialog from presets.
    * [#5127](https://github.com/ckeditor/ckeditor4/issues/5127): Deprecated the
    [`CKEDITOR.rnd`](https://ckeditor.com/docs/ckeditor4/latest/api/CKEDITOR.html#property-rnd) property to
    discourage using it in a security-sensitive context.
    * [#5087](https://github.com/ckeditor/ckeditor4/issues/5087): Improved the jQuery adapter by replacing a
    deprecated jQuery API with existing counterparts. Thanks to [Fran Boon](https://github.com/flavour)!
    * [#5128](https://github.com/ckeditor/ckeditor4/issues/5128): Improved the
    [Emoji](https://ckeditor.com/cke4/addon/emoji) definitions encoding set by the
    [`config.emoji_emojiListUrl`](https://ckeditor.com/docs/ckeditor4/latest/api/CKEDITOR_config.html#cfg-
    emoji_emojiListUrl) configuration option.

    ## CKEditor 4.17.2

    Fixed issues:

    * [#4934](https://github.com/ckeditor/ckeditor4/issues/4934): Fixed: Active focus in dialog tabs is not
    visible in the High Contrast mode.
    * [#547](https://github.com/ckeditor/ckeditor4/issues/547): Fixed: Dragging and dropping elements like
    images within a table is no longer available.
    * [#4875](https://github.com/ckeditor/ckeditor4/issues/4875): Fixed: It is not possible to delete multiple
    selected lists.
    * [#4873](https://github.com/ckeditor/ckeditor4/issues/4873): Fixed: Pasting content from MS Word and
    Outlook with horizontal lines prevents images from being uploaded.
    * [#4952](https://github.com/ckeditor/ckeditor4/issues/4952): Fixed: Dragging and dropping images within a
    table cell appends additional elements.
    * [#4761](https://github.com/ckeditor/ckeditor4/issues/4761): Fixed: Some CSS files are missing unique
    timestamp used to prevent browser to cache static resources between editor releases.
    * [#4987](https://github.com/ckeditor/ckeditor4/issues/4987): Fixed:
    [Find/Replace](https://ckeditor.com/cke4/addon/find) is not recognizing more than one space character.
    * [#5061](https://github.com/ckeditor/ckeditor4/issues/5061): Fixed:
    [Find/Replace](https://ckeditor.com/cke4/addon/find) plugin incorrectly handles multiple whitespace during
    replacing text.
    * [#5004](https://github.com/ckeditor/ckeditor4/issues/5004): Fixed: `MutationObserver` used in [IFrame
    Editing Area](https://ckeditor.com/cke4/addon/wysiwygarea) plugin causes memory leaks.
    * [#4994](https://github.com/ckeditor/ckeditor4/issues/4994): Fixed: [Easy
    Image](https://ckeditor.com/cke4/addon/easyimage) plugin caused content pasted from Word to turn into an
    image.

    API changes:

    * [#4918](https://github.com/ckeditor/ckeditor4/issues/4918): Explicitly set the
    [`config.useComputedState`](https://ckeditor.com/docs/ckeditor4/latest/api/CKEDITOR_config.html#cfg-
    useComputedState) default value to `true`. Thanks to [Shabab Karim](https://github.com/shabab477)!
    * [#4761](https://github.com/ckeditor/ckeditor4/issues/4761): The
    [`CKEDITOR.appendTimestamp()`](https://ckeditor.com/docs/ckeditor4/latest/api/CKEDITOR.html#method-
    appendTimestamp) function was added.
    * [#4761](https://github.com/ckeditor/ckeditor4/issues/4761): [`CKEDITOR.dom.document#appendStyleSheet()`]
    (https://ckeditor.com/docs/ckeditor4/latest/api/CKEDITOR_dom_document.html#method-appendStyleSheet) and [`
    CKEDITOR.tools.buildStyleHtml()`](https://ckeditor.com/docs/ckeditor4/latest/api/CKEDITOR_tools.html#metho
    d-buildStyleHtml) now use the newly added
    [`CKEDITOR.appendTimestamp()`](https://ckeditor.com/docs/ckeditor4/latest/api/CKEDITOR.html#method-
    appendTimestamp) function to correctly handle caching of CSS files.

    Other changes:

    * [#5014](https://github.com/ckeditor/ckeditor4/issues/5014): Fixed: Toolbar configurator fails when
    plugin does not define a toolbar group. Thanks to [SuperPat](https://github.com/SuperPat45)!

    ## CKEditor 4.17.1

    **Highlights:**

    Due to a regression in CKEeditor 4.17.0 version that was only revealed after the release and affected a
    limited area of operation, CSS assets loaded via relative links started to point into invalid location
    when loaded from external resources.

    We have therefore decided to immediately release CKEditor 4.17.1 that fixed this problem. If you have
    already upgraded to v4.17.0, make sure to upgrade to v4.17.1 to avoid this regression.

    Fixed issues:

    * [#4979](https://github.com/ckeditor/ckeditor4/issues/3757): Fixed: Added cache key in
    [#4761](https://github.com/ckeditor/ckeditor4/issues/4761) started to breaking relative links for external
    CSS resources. The fix has been reverted and will be corrected in the next editor version.

    ## CKEditor 4.17

    **Security Updates:**

    * Fixed XSS vulnerability in the core module reported by [William Bowling](https://github.com/wbowling).

            Issue summary: The vulnerability allowed to inject malformed comments HTML bypassing content
    sanitization, which could result in executing JavaScript code. See
    [CVE-2021-41165](https://github.com/ckeditor/ckeditor4/security/advisories/GHSA-7h26-63m7-qhf2) for more
    details.

    * Fixed XSS vulnerability in the core module reported by [Maurice Dauer](https://twitter.com/laytonctf).

            Issue summary: The vulnerability allowed to inject malformed HTML bypassing content sanitization,
    which could result in executing JavaScript code. See
    [CVE-2021-41164](https://github.com/ckeditor/ckeditor4/security/advisories/GHSA-pvmx-g8h5-cprj) for more
    details.

    You can read more details in the relevant security advisory and [contact us](security@cksource.com) if you
    have more questions.

    **An upgrade is highly recommended!**

    **Highlights:**

    Adobe [ended support of Flash Player](https://www.adobe.com/products/flashplayer/end-of-life.html) on
    December 31, 2020 and blocked Flash content from running in Flash Player beginning January 12, 2021.
    We have decided to deprecate and remove the [Flash](https://ckeditor.com/cke4/addon/flash) plugin from
    CKEditor 4 to help protect users' systems and discourage using insecure software.

    New Features:

    * [#3433](https://github.com/ckeditor/ckeditor4/issues/3433): Marked required fields in dialogs with
    asterisk (`*`) symbol.
    * [#4374](https://github.com/ckeditor/ckeditor4/issues/4374): Integrated the
    [Maximize](https://ckeditor.com/cke4/addon/maximize) plugin with browser's History API.
    * [#4461](https://github.com/ckeditor/ckeditor4/issues/4461): Introduced the possibility to delay editor
    initialization while it is in a detached DOM element.
    * [#4462](https://github.com/ckeditor/ckeditor4/issues/4462): Introduced support for reattaching editor
    container element to DOM.
    * [#4612](https://github.com/ckeditor/ckeditor4/issues/4612): Allow pasting images as Base64 from
    [clipboard](https://ckeditor.com/cke4/addon/clipboard) in all browsers except IE.
    * [#4681](https://github.com/ckeditor/ckeditor4/issues/4681): Allow drag and drop images as Base64.
    * [#4750](https://github.com/ckeditor/ckeditor4/issues/4750): Added notification for pasting and dropping
    unsupported file types into the editor.
    * [#4807](https://github.com/ckeditor/ckeditor4/issues/4807): [Chrome] Improved the performance of pasting
    large images. Thanks to [FlowIT-JIT](https://github.com/FlowIT-JIT)!
    * [#4850](https://github.com/ckeditor/ckeditor4/issues/4850): Added support for loading [content
    templates](https://ckeditor.com/cke4/addon/templates) from HTML files. Thanks to
    [Fynn96](https://github.com/Fynn96)!
    * [#4874](https://github.com/ckeditor/ckeditor4/issues/4874): Added the
    [`config.clipboard_handleImages`](https://ckeditor.com/docs/ckeditor4/latest/api/CKEDITOR_config.html#cfg-
    clipboard_handleImages) configuration option for enabling and disabling built-in support for pasting and
    dropping images in the [Clipboard](https://ckeditor.com/cke4/addon/clipboard) plugin. Thanks to [FlowIT-
    JIT](https://github.com/FlowIT-JIT)!
    * [#4026](https://github.com/ckeditor/ckeditor4/issues/4026):
    [Preview](https://ckeditor.com/cke4/addon/preview) plugin now uses the [`editor#title`](http://localhost/c
    keditor4-docs/build/docs/ckeditor4/latest/api/CKEDITOR_editor.html#property-title) property for the title
    of the preview window. Thanks to [Ely](https://github.com/Elyasin)!
    * [#4467](https://github.com/ckeditor/ckeditor4/issues/4467): Added support for inserting content next to
    a block [widgets](https://ckeditor.com/cke4/addon/widget) using keyboard navigation. Thanks to
    [bunglegrind](https://github.com/bunglegrind)!

    Fixed Issues:

    * [#3757](https://github.com/ckeditor/ckeditor4/issues/3757): [Firefox] Fixed: images pasted from
    [clipboard](https://ckeditor.com/cke4/addon/clipboard) are not inserted as Base64-encoded images.
    * [#3876](https://github.com/ckeditor/ckeditor4/issues/3876): Fixed: The
    [Print](https://ckeditor.com/cke4/addon/print) plugin incorrectly prints links and images.
    * [#4444](https://github.com/ckeditor/ckeditor4/issues/4444): [Firefox] Fixed: Print preview is
    incorrectly loaded from CDN.
    * [#4596](https://github.com/ckeditor/ckeditor4/issues/4596): Fixed: Incorrect handling of HSL/HSLA values
    in [`CKEDITOR.tools.color`](https://ckeditor.com/docs/ckeditor4/latest/api/CKEDITOR_tools_color.html).
    * [#4597](https://github.com/ckeditor/ckeditor4/issues/4597): Fixed: Incorrect color conversion for
    HSL/HSLA values in
    [`CKEDITOR.tools.color`](https://ckeditor.com/docs/ckeditor4/latest/api/CKEDITOR_tools_color.html).
    * [#4604](https://github.com/ckeditor/ckeditor4/issues/4604): Fixed: [`CKEDITOR.plugins.clipboard.dataTran
    sfer#getTypes()`](https://ckeditor.com/docs/ckeditor4/latest/api/CKEDITOR_plugins_clipboard_dataTransfer.h
    tml#method-getTypes) returns no types.
    * [#4761](https://github.com/ckeditor/ckeditor4/issues/4761): Fixed: Not all resources loaded by the
    editor respect the cache key.
    * [#4783](https://github.com/ckeditor/ckeditor4/issues/4783): Fixed: The [Accessibility
    Help](https://ckeditor.com/cke4/addon/a11yhelp) dialog does not contain info about focus being moved back
    to the editing area upon activating a toolbar button.
    * [#4790](https://github.com/ckeditor/ckeditor4/issues/4790): Fixed: Printing page is invoked before the
    printed page is fully loaded.
    * [#4874](https://github.com/ckeditor/ckeditor4/issues/4874): Fixed: Built-in support for pasting and
    dropping images in the [Clipboard](https://ckeditor.com/cke4/addon/clipboard) plugin restricts third party
    plugins from handling image pasting. Thanks to [FlowIT-JIT](https://github.com/FlowIT-JIT)!
    * [#4888](https://github.com/ckeditor/ckeditor4/issues/4888): Fixed: The
    [`CKEDITOR.dialog#setState()`](https://ckeditor.com/docs/ckeditor4/latest/api/CKEDITOR_dialog.html#method-
    setState) method throws error when there is no OK button in the dialog.
    * [#4858](https://github.com/ckeditor/ckeditor4/issues/4858): Fixed: The
    [Autolink](https://ckeditor.com/cke4/addon/autolink) plugin incorrectly escapes the `&` characters when
    pasting links into the editor.
    * [#4892](https://github.com/ckeditor/ckeditor4/issues/4892): Fixed: Focus of buttons in dialogs is not
    visible enough in High Contrast mode.
    * [#3858](https://github.com/ckeditor/ckeditor4/issues/3858): Fixed: Pasting content in `ENTER_BR` [enter
    mode](https://ckeditor.com/docs/ckeditor4/latest/api/CKEDITOR_config.html#cfg-enterMode) crashes the
    editor.
    * [#4891](https://github.com/ckeditor/ckeditor4/issues/4891): Fixed: The
    [Autogrow](https://ckeditor.com/cke4/addon/autogrow) plugin applies fixed width to the editor.

    API Changes:

    * [#4462](https://github.com/ckeditor/ckeditor4/issues/4462): [`CKEDITOR.editor#getSelection()`](https://c
    keditor.com/docs/ckeditor4/latest/api/CKEDITOR_editor.html#method-getSelection) now returns `null` if the
    editor is in recreating state.
    * [#4583](https://github.com/ckeditor/ckeditor4/issues/4583): Added support for new, comma-less color
    syntax to
    [`CKEDITOR.tools.color`](https://ckeditor.com/docs/ckeditor4/latest/api/CKEDITOR_tools_color.html).
    * [#4604](https://github.com/ckeditor/ckeditor4/issues/4604): Added the [`CKEDITOR.plugins.clipboard.dataT
    ransfer#isFileTransfer()`](https://ckeditor.com/docs/ckeditor4/latest/api/CKEDITOR_plugins_clipboard_dataT
    ransfer.html#method-isFileTransfer) method.
    * [#4790](https://github.com/ckeditor/ckeditor4/issues/4790): Added `callback` parameter to [`CKEDITOR.plu
    gins.preview#createPreview()`](https://ckeditor.com/docs/ckeditor4/latest/api/CKEDITOR_plugins_preview.htm
    l#method-createPreview) method.

    Other Changes:

    * [#4866](https://github.com/ckeditor/ckeditor4/issues/#4866): The
    [Flash](https://ckeditor.com/cke4/addon/flash) plugin is now deprecated and has been removed from CKEditor
    4.
    * [#4901](https://github.com/ckeditor/ckeditor4/issues/4901): Redesigned buttons placement in the [Content
    templates](https://ckeditor.com/cke4/addon/templates) dialog to make it more UX friendly. Thanks to
    [Fynn96](https://github.com/Fynn96)!

Tenable has extracted the preceding description block directly from the Fedora security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2022-4c634ee466");
  script_set_attribute(attribute:"solution", value:
"Update the affected ckeditor package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-24728");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/11/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:37");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ckeditor");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Fedora Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Fedora' >!< os_release) audit(AUDIT_OS_NOT, 'Fedora');
var os_ver = pregmatch(pattern: "Fedora.*release ([0-9]+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Fedora');
os_ver = os_ver[1];
if (! preg(pattern:"^37([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Fedora 37', 'Fedora ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Fedora', cpu);

var pkgs = [
    {'reference':'ckeditor-4.20.0-1.fc37', 'release':'FC37', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (reference && _release) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_NOTE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ckeditor');
}
