# Process Manager

This is an entirely async process manager... there are many ways that a
process who's output is being captured can transition. It took me a little
while to see them all and handle them properly.

## Process States

* `EXTPROCESS_STATE_INIT`
* `EXTPROCESS_STATE_RUNNING`
* `EXTPROCESS_STATE_STOPPING`
* `EXTPROCESS_STATE_STOPPED`
* `EXTPROCESS_STATE_FINISHED`

## Test Read

Test 3 reads a file from `inputfile.bin` using cat and writes the content
to `outputfile.bin` check that the read and written data is the same by
checking the size and SHASUM:

    dd if=/dev/urandom of=inputfile.bin bs=5M count=1
    testsrc/pm_test
    sha1sum inputfile.bin outputfile.bin

## Cleaning the Repository

This command will remove all generated and created files (such as the
`.cache` and `build` directories).

    git clean -x -f -d

This will undo all changes to files tracked by git:

    git reset --hard
