# conda auth

A conda plugin for handling authenticated access to private channels.

Conda auth currently supports the following types of authentication:

- HTTP Basic Authentication

On top of this, conda auth supports session management via two subcommands for logging into services (`conda auth login`) and logging out of services (`conda auth logout`).

## Installation

Conda auth is available on conda-forge. As with all conda plugins, this must be installed into your base environment:
```
conda install --name base --channel conda-forge conda-auth
```

## Usage

**Log in** to a channel protected by HTTP basic authentication:

```
conda auth login https://example.com/my-protected-channel --username $USERNAME
```

**Log out** of a channel to remove credentials from your computer:

```
conda auth logout https://example.com/my-protected-channel
```


## Contributing to This Project

Contributions are very welcome to this project! 

Feel free to:
1. File bug reports
2. Create feature requests
3. Open pull requests to resolve issues available in the [Github issues queue](https://github.com/conda-incubator/conda-auth/issues).
4. Review open pull requests
5. Report any typos, wrong/outdated information on the [documentation website](https://conda-incubator.github.io/conda-auth/).
6. Engage in ongoing discussions in this project and add new ideas.

Head to the [Developers Guide](https://conda-incubator.github.io/conda-auth/dev/) for this project to learn how to set up your development environment. 

Do join the [conda Matrix chat](https://app.element.io/#/room/#conda:matrix.org) to get in touch with the rest of conda community and post any questions that you might have. 

Happy Contributing!
