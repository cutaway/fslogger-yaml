# fslogger-yaml
Patched version of fslogger to output data in YAML format. Current versions of fslogger output data in ASCII format which makes review and reporting easy but parsing difficult. YAML formatting means that other parsers can be developed to extract specific information and output in other formats. Hopefully this makes analysis easier.

* [fslogger](https://gist.github.com/walkie/6282157) - an update of the [original fslogger](http://osxbook.com/software/fslogger/)
  * Requires [OpenSource XNU](https://github.com/opensource-apple/xnu) to compile. No need to build, just run the compilation line in the build instructions.
* [fswatch](https://github.com/emcrisostomo/fswatch) - a similar project that might meet your needs.
  * [FSW](https://github.com/emcrisostomo/fsw) was created to replace fswatch but then they merged and fswatch became primary, again.

## Compile fslogger-yaml

Compiling requires Apple's [OpenSource XNU[(https://github.com/opensource-apple/xnu). Clone this into the fslogger-yaml working directory and provide GCC with the BSD libraries location.

```bash
cutaway> gcc -I./xnu/bsd -Wall -o fslogger-yaml fslogger-yaml.c
```

## Usage
Data is output to STDOUT.
```bash
cutaway> sudo ./fslogger-yaml
```

Data is redirected to file "test-output.yaml".
```bash
cutaway> sudo ./fslogger-yaml >test-output.yaml
```

Data is output to the file "test-output.yaml".
```bash
cutaway> sudo ./fslogger-yaml test-output.yaml
```

## Parsing with fslogger-yaml-python
Python parser currently only provides examples of outputing Process IDs, Process Names, and File names.

```bash
cutaway> python fslogger-yaml-parser.py test-fslogger-yaml3.txt
```

## Avoiding Recursive File Event Logging
Writing to a file on the system that you are monitoring changes can lead to concerns about creating and logging file system activity. Not writing these changes can be done programmatically but this could lead to processing delays that may have a negative impact on performance. Performance issues could lead to dropped events and force Spotlight or Time Machine, which have priority over FSEvents, to perform additional actions and delay processing further.

One alternative is to write the output of fslogger-yaml to a separate, appropriately prepared volume. This is outlined in the [FSEvent documentation](
https://developer.apple.com/library/mac/documentation/Darwin/Conceptual/FSEvents_ProgGuide/FileSystemEventSecurity/FileSystemEventSecurity.html#//apple_ref/doc/uid/TP40005289-CH6-SW1).

```
Preventing File System Event Storage

In some cases, the contents of a volume are sufficiently secret that it is not appropriate to log them. To disable logging on a per-volume basis (for creating a backup volume, for example), you must do the following:

Create a .fseventsd directory at the top level of the volume.
Create an empty no_log file in that directory.
So if your volume is mounted at /Volumes/MyDisk, you would create an empty file called /Volumes/MyDisk/.fseventsd/no_log.
```

## TODO
* Update python parser to provide more functionality and output useful information.
* Add ruby parser <- John H. Sawyer?


