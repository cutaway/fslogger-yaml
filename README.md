# fslogger-yaml
Patched version of fslogger to output data in YAML format. Current versions of fslogger output data in ASCII format which makes review and reporting easy but parsing difficult. YAML formatting means that other parsers can be developed to extract specific information and output in other formats. Hopefully this makes analysis easier.

* [fslogger](https://gist.github.com/walkie/6282157) - an update of the [original fslogger](http://osxbook.com/software/fslogger/)
  * Requires [OpenSource XNU[(https://github.com/opensource-apple/xnu) to compile. No need to build, just run the compilation line in the build instructions.
* [fswatch](https://github.com/emcrisostomo/fswatch) - a similar project that might meet your needs.
  * [FSW](https://github.com/emcrisostomo/fsw) was created to replace fswatch but then they merged and fswatch became primary, again.

## Compile fslogger-yaml

Compiling requires Apple's [OpenSource XNU[(https://github.com/opensource-apple/xnu). Clone this into the fslogger-yaml working directory and provide GCC with the BSD libraries location.

```bash
cutaway> gcc -I./xnu/bsd -Wall -o fslogger-yaml fslogger-yaml.c
cutaway> sudo ./fslogger-yaml >test-fslogger-yaml3.txt
Password:
```

## Parsing with fslogger-yaml-python
Python parser currently only provides examples of outputing Process IDs, Process Names, and File names.

```bash
cutaway> python fslogger-yaml-parser.py test-fslogger-yaml3.txt
```

## TODO
* Update fslogger-yaml to accept paths and process information to limit data collected.
* Update python parser to provide more functionality and output useful information.
* Add ruby parser <- John H. Sawyer?


