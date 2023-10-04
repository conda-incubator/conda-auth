# conda auth <i class="fa-solid fa-user-lock" style="color: #828282; font-size: 30px"></i>

```{toctree}
:maxdepth: 1
:hidden:

User Guide <user/index>
Developer Guide <dev/index>
```


Conda auth is a conda plugin which adds more secure authentication support to conda.

Once installed, it provides two new commands you can use to authenticate against
protected, private conda channels:

- `conda auth login` for logging into and storing your credentials
- `conda auth logout` for logging out of and remove your credentials

## Examples

**Log in** to a channel protected by HTTP basic authentication:

```
conda auth login https://example.com/my-protected-channel --username $USERNAME
```

**Log out** of a channel to remove credentials from your computer:

```
conda auth logout https://example.com/my-protected-channel
```

## Installation

To start using conda auth, we recommend installing to your base environment:

```
conda install --name base --channel conda-forge conda-auth
```

<hr style="margin-bottom: 2em; margin-top: 2em" />

::::{grid} 2
:::{grid-item-card}

<div style="text-align: center">
    <h3 style="margin-top: 0.5em">User Guide</h3>
    <p>To learn even more about how to use conda auth head over to our user guide</p>
</div>

```{button-ref} user/index
:expand:
:color: primary

To the user guide
```

:::

:::{grid-item-card}

<div style="text-align: center">
    <h3 style="margin-top: 0.5em">Developer Guide</h3>
    <p>Are you interested in contributing to conda auth? Our contributing guidelines will help you get up and running.</p>
</div>

```{button-ref} dev/index
:expand:
:color: info

To the developer guide
```
:::

::::
