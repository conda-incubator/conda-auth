# Contributing

```{toctree}
:maxdepth: 1
:hidden:

Code of Conduct <code-of-conduct>
Release Notes <changelog>
```

Thank you for your interest in contributing to conda auth! This is a short guide that will walk you
through all the steps necessary to contribute code to the project.

## Finding an issue to work on

Finding an open issue to work on is the most important part when contributing. To see what's currently
available, head over to the [GitHub issues queue][issues-queue].

If you have any questions about any open issues, please feel free to reach out to the maintainers via
our [Element chat room][element-chat].

```{admonition} Tip
Please be sure that the issue is open before working on it. If you would like to work on it, ask in
the comments or ping the conda-auth maintainers on Element.
```

## Setting up your development environment

### Prerequisites

Before setting up your development environment, please make sure that conda is installed
and is at the latest version. Also, make sure to create a fork of the repository in GitHub
and clone the forked repository to your local computer.

### Creating the development environment

#### Using conda

To set up your development environment, follow these steps:

1. Set up the development environment with these commands:
   ```
   conda env create -n conda-auth-dev -f environment.yml
   ```
2. Next, you will want to activate the environment:
   ```
   conda activate conda-auth-dev
   ```
3. Install the `conda-auth` package locally as editable with `pip`:
   ```
   pip install -e .
   ```
4. Point your shell session to the correct conda executable to use:
   ```
   export CONDA_EXE="$CONDA_PREFIX/bin/conda"
   ```
5. To verify the installation, run the `conda` command with no arguments and make sure `auth` shows up under
   the list of available commands.


#### Using pixi

You can also use the pixi package manager to set up your development environment.
If pixi is not already installed on your computer, please visit their
[installation guide](https://pixi.sh/latest/#installation).

To set up your development environment, follow these steps:

1. Set up and activate the development environment with these commands:
   ```
   pixi install
   pixi run develop
   ```
2. Next, you will want to start a new shell with the following command:
   ```
   pixi shell
   ```
3. To verify the installation, run the `conda` command with no arguments and make sure `auth` shows up under
   the list of available commands.

Once this has been done, you should be ready to start make changes to the conda-auth plugin and
experimenting with it on your computer.

### Running tests

#### Using conda

To run the test for conda-auth, run the following command:

```
pytest --doctest-modules
```

Or, to generate an HTML coverage report, run with the following command:

```
pytest --cov=conda_auth --cov-report=html --doctest-modules
```

#### Using pixi

To run the test for conda-auth, run the following command:

```
pixi run --environment dev test
```

Or, to generate an HTML coverage report, run with the following command:

```
pixi run --environment dev testhtml
```

If you want to run tests for different Python versions, we have configured this
project to use all the latest supported versions. You can do so by specifying
them via the `--environment` option:

```bash
# For Python 3.10
pixi run --environment dev-py310 test
```

```bash
# For Python 3.9
pixi run --environment dev-py39 test
```

## Submitting a pull request

Once you are ready to submit your code for review, submit a pull request via GitHub. Please be sure to link
it to the open issue you are working on.

<!-- Hyperlinks -->

[issues-queue]: https://github.com/conda-incubator/conda-auth/issues
[element-chat]: http://bit.ly/conda-chat-room
