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
