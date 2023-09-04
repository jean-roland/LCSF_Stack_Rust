## Presentation

LCSF Stack Rust is a Rust implementation of the LCSF (Light Command Set Format).

This adds a software layer to easily encode/decode custom command sets based on LCSF to your project.

## About LCSF

LCSF is a specification to easily create and deploy custom command sets.

For more information on the project, check the official LCSF documentation [here](https://jean-roland.github.io/LCSF_Doc/).

## How to use

*WIP* Install as source code or crate

Then, to interface with your project:
* Create a custom protocol either by modifying the example protocol files or by using the [LCSF Generator](https://github.com/jean-roland/LCSF_Generator) (recommended).
* Instantiate a `LcsfCore` object with the desired parmeters, example of how to use this object can be found in this repo's `Main.rs`.

## How the stack works

The stack itself is composed of 4 files:
* `lcsf_transcoder`: Serialize/Deserialize `LcsfRawMsg` objects to and from `byte array`.
* `lcsf_validator`: Validate/Encode `LcsfRawMsg` into `LcsfValidCmd` following a protocol descriptor object `LcsfProtDesc`
* `lcsf_error`: Handle the processing/creation of the built-in LCSF Error Protocol. For more information on this, check the LCSF documentation.
* `lcsf_core`: The core file that links all the other parts together into a simple to use object.

*WIP* Block diagram

## Parameters

When instantiatings your `LcsfCore` object you have to feed three parameters:
* `mode: LcsfModeEnum`, indicates the lcsf representation to use, either Small or Normal. For more information on this, check the LCSF documentation.
* `send_cb: fn pointer`, a function pointer to receive the encoded lcsf frame and send them wherever they're needed.
* `do_gen_err: bool`, indicates if the module will generate error frame when decoding an incoming message fails.

## Protocol files

*WIP* Not yet defined

## Note on recursivity

Since LCSF is based on nested structures, the stack use recursive functions.

Recursivity can be frowned upon, which is why the stack is made to limit the issue:
* The number of calls is directly linked to the number of sub-attribute layers in a protocol, that means the user has direct control.
* The stack is linear in its recursivity (one call will only lead to a maximum of one other call).

## Build, tests & docs

If you want to run the project as is use `cargo run`

To run the test suite use `cargo test`

To generate the doc use `cargo doc`, you can access the documentation at `target/doc/help.html`.

## Resource usage

*WIP* do some benchmarking
