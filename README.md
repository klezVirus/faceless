# faceless

Faceless is a script useful to anonymize a file which contains specific types of potentially sensitive information, such as ip addresses, emails, domain names and others.

## Overview

The idea behind anonymization is very simple, replace any data which holds sensitive (or potentially sensitive) information with other data with similar properties, but no informational value in the data context used. 

A silly but effective approach would be just replacing certain values with random ones. While this may work in many circumstances, the main drawback would be that data would be lost in the process.

Another approach would be replacing sensitive values with hashes, creating a map which could then be used later to restore the data. While this approach is surely better, just placing hashes in a file containing other data might compromise both its semantic and syntax.

Faceless uses an hybrid approach, random data is generated to replace original values, but respecting the original format (ip -> ip, email -> email). In addition, a map is generate to allow full data recovery in a later phase.

## Usage

Using faceless is not immediately straightforward, as observable by the help below, but it becomes easy as soon as its internals are exposed.

```
$ python faceless.py -h
usage: faceless.py [-h] [-c CHECK] [-u] [-g] [-m MAPPING] [-d] -i FILE [-f FILTERS]

Faceless: A script to anonymize/deanonimize various files 

optional arguments:
  -h, --help            show this help message and exit
  -c CHECK, --check CHECK
                        Check common regex
  -u, --unique          Print just first occurrence
  -g, --generate        Attempt to automatically generate a mapping
  -m MAPPING, --mapping MAPPING
                        Mapping File
  -d, --debug           Enable debug output
  -i FILE, --file FILE  File to anonymize
  -f FILTERS, --filters FILTERS
                        Filter set in string form
  -r, --restore         Apply a reverse mapping
```

#### Key arguments

###### File (-i)
The only required field is the input file, which represents the file to be anonymized.

###### Check (-c)
If the `-c` flag is set, faceless will check for common regex in the file, showing all the matches in the console screen. the c flag has to be used in combination with the common regex to check for in the file. Currently, the supported regex types are the following:

* Windows path (winpath)
* Domain Names (domain)
* IP Addresses (ip)
* Email Addresses (email)
* URLs (url)
* All (*)

The check can be done using multiple regex types using the separator "::", as showed below:

```
// Search all IP, Domain Names and Email Addresses
./faceless -i file.xml -c ip::domain::email
```

This may be useful to check which matches are good, and to prepare a filter to exclude the false positives. A small example is provided further on.

###### Unique (-u)
If the flag `-u` is set, only unique matches will be showed to the console.

###### Generate (-g)
If the flag `-g` is set, faceless will try to generate a mapping file. The mapping file is a file used to store tracks of the data changed during the anonymisation process, allowing for a revert. For technical detail about mapping files, please see below. 

###### Restore(-r)
If the flag `-r` is set, faceless will try to restore the original file, applying a reverse mapping (i.e. the mapping file in a mirrored fashion).

###### Filters (-f)
The filter flag can be set to a stringified filter set. A filter set is a data structure used to represent, at a basic level, exclusion and inclusion filters. 

The basic syntax used by the filter string is detailed further on.
 
#### Filter syntax

A filter set can be represented by a string using the following syntax: 

```
key_1::[--|++]filter_1_1..[--|++]filter_1_2§§key_2::[--|++]file_2_1..[--|++]file_2_n
```

Where:

* `key_i`: A value in ["ip", "domain", "winpath", "url", "email" ]
* `filter_i_j`: A Python regex/string
* `++`: Includes lines that match the filter
* `--`: Excludes lines that match the filter

###### Filter ordering

The filter chain used for each regex type is applied taking into account the first regex used, using the following rationale:

* `(Filter 1 == ++ filter)`: Include only matches to ++ filter and exclude every -- selected
* `(Filter 1 == -- filter)`: Exclude only matches to -- filter and include every ++ selected

**Example**

`ip::--10.0.0.*..++10.0.0.1`

When parsed, the above filter would exclude all IP in range 10.0.0.*, except 10.0.0.1.

The filter logic has been implemented to be able to filter values that resemble a valid regex, but are not.

* Numbered paragraphs match IP regex (e.g. 1.1.1.2)
* Nasty executables match domain regex (e.g my.nasty.exe)

#### Mapping files

Informally, mapping files are textual files use to track changes made during the anonymisation, associating all the strings replaced in a file with their anonymized value.

A bit more formally, let W be the set of all possible text strings, a mapping is a function:
```
m: W -> W
```

A mapping M can be represented as a list of pairs (x,y), where x is a word in W, while y is a randomly generated replacement of x.

###### Anonymization and mappings

The algorithm is implemented to generate a mapping prior to attempt a full anonymization. Giving the user the possibility to recheck and manually tamper values. After that, the algorithm proceeds and simply apply the generated mapping.

This mechanism allows the user to fully restore the data, as long as he does possess the correct mapping for the anonymized file.