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

## Cleaning the Repository

This command will remove all generated and created files (such as the
`.cache` and `build` directories).

    git clean -x -f -d

This will undo all changes to files tracked by git:

    git reset --hard
