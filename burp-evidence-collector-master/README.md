# Burp Suite extension: Evidence Collector 2.0

## Update notes
- Ability to add text files & images (from source or clipboard)
- General quality-of-life fixes
- Evidence template system to further generalize and speed-up our reporting-style
- ... TODO


## Description
This extension allows pentesters to easily create/manage/export **evidences** and **findings** for reporting purposes.

A **finding** is a discovered vulnerability proven by **evidence files** which are requests and responses from and to the vulnerable system.

The plugin provides a central place within Burp Suite to manage created evidence files. It offers the following functionality:
- Hold notes and multiple evidence files for a given finding
- (Automatically) redact sensitive data from headers
- Export evidence files
- Load evidence files 
- Dynamically create evidence files


## Installation
This Burp Suite extension is written in Python, therefore you must download the latest version of Jython interpreter. It is a [standalone jar](https://www.jython.org/download) which you need to add to Burp Suite in Extender > Options > Python Environment.

For more information on how to add Jython extensions to Burp Suite click [here](https://support.portswigger.net/customer/portal/articles/1965930-how-to-install-an-extension-in-burp-suite)

After configuring Jython you can add the burp-extender.py file to Burp Suite in Extender > Extensions


## Usage

The extension has three tabs: Overview, Import/Export, Configuration

To add a finding simply RMB on a request from anywhere within Burp Suite and select Evidence Collector > Create a new finding

###  Overview
This tab contains two custom JTables on the left side which show the existing findings and evidences. On the right side it has a textarea for notes and a request- and responseviewer.

Click on a finding to view the corresponding evidence files and notes. You can modify the requests/responses as you wish, the changes will be saved as soon as you select a different component within Burp Suite. To delete a finding or evidence RMB on the entry in the table and select "delete".

Each finding has a severity level which decides the order in which the findings will be exported.

To remove senstive headers or values from the request/response, highlight the values and click "Include selected data" to remove everything except the selection or click "Exclude selected data" to only remove the highlighted part.

Note that the request- and responseviewers don't support CTRL-Z when you remove headers via these buttons. In case too much data was removed you can click on "revert to original" to obtain the original message again.

### Import/Export
Here you can export the findings at a location. Note that it will create a directory 'Evidences' at the specified location and here it will create a directory for every existing finding. The name of these directories is prefixed by the value in the finding ID textbox. The evidence files and the notes will be exported in their finding directories as .txt files. 

It will also create an evidences.ser file. This file is crucial to load evidences back in the plugin. Simply navigate to the location of the Evidences directory or the location of the evidences.ser file and click "Load Now". 

Next to importing and exporting manually there is also an option to autosave. This will create all the finding directories and evidence files as you add them to the plugin. Please bear in mind that this option will create and remove directories automatically and even though I tested it to the best of my ability it may perform unexpected behaviour and cause loss of data. 

### Configuration
In this tab you can add headers of which the values should be redacted. When you add an evidence file to the plugin the value of the header will be replaced by "< SNIP >"

You can also modify how the notes and evidence files should look like, including how they are named.

## Good to know
- Do not forget to save the findings before closing the project (or simply turn on auto-save).
- It's important that the evidences.ser exists witin an "Evidences" directory.
- If you provide a relative path for the export, the evidences will be exported to the installation directory of Burp Suite or to the home directory of the current user.
- It is important that you don't manually rename finding directories or evidence files in the filesystem while the autosave option is active. 
- In Unix-like systems the exported evdidence files might contain the ^M char at the end of the lines. This is the windows carriage return (\r) which can be removed by running it through dos2unix `dos2unix -n infile outfile`
- Don't nest an Evidence directory within an Evidence directory or you might lose the former
- Avoid using special ASCII characters in finding descriptions as they might not be included in the exported results

## Authors and acknowledgment
This plugin is created by a student as part of an internship at NVISO. Therefore it may contain code which could be improved :)

Shout-out to Vincent De Schutter and Timo Vergauwen for providing valuable feedback during and after the course of the development.

A big thanks to everyone who gave suggestions for improvement.
