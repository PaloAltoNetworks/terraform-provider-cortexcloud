# How to Contribute

First off, thanks for taking the time to contribute! Following these guidelines helps keep the project maintainable, easy to contribute to, and more secure.

## Where to start
There are many ways to contribute.
You can fix a bug, improve the documentation, submit bug reports and feature requests, or take a first shot at a feature you need for yourself.

Pull requests are necessary for all contributions of code or documentation.

## Fixing a typo or other small issue
Many fixes require little effort or review, such as:

- Typos, white space and formatting changes
- Comment clean up
- Change logging messages or debugging output

These small changes can be made directly in GitHub if you like.

In the GitHub web UI, click the pencil icon above the file to edit the file directly in your browser.
This will automatically create a fork and pull request with the change.
See: [Creating a pull request](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/proposing-changes-to-your-work-with-pull-requests/creating-a-pull-request)

## Bug fixes and features
For something that is bigger than a one or two line fix, go through the process of making a fork and pull request yourself:

1. Create your own fork of the code
2. Clone the fork locally
3. Make the changes in your local clone
4. Push the changes from your local clone to your remote fork
5. Create a pull request in the main repository to pull the changes from your fork.

The pull request should be a single commit.

Please use a clear commit message. We'll review every PR and might offer feedback or request changes before merging.

# Contributing

If you're interested in contributing to the development of the provider, see below for a basic startup guide.

## Prerequisites

- Go 1.24.0+
  - `brew install go`
- Terraform 1.13.0+
  - `brew tap hashicorp/tap`
  - `brew install hashicorp/tap/terraform`


## Makefile

See the [Makefile](Makefile) for available `make` targets.

## Local Installation

Copy the configuration below into your `$HOME/.terraformrc` file to force Terraform to use your locally-built version of the provider when testing changes. Be sure to change the `path` value in the `filesystem_mirror` block to your local Terraform plugin directory (typically `$HOME/terraform.d/plugins`).

```
provider_installation {
  filesystem_mirror {
    path    = "~/.terraform.d/plugins"
    include = ["registry.terraform.io/PaloAltoNetworks/cortexcloud"]
  }
  direct {
    exclude = ["registry.terraform.io/PaloAltoNetworks/cortexcloud"]
  }
}
```

## Testing

Run `make test` to run the unit and acceptance test suites.

Note that acceptance tests require you to have the following environment variables configured against an existing Cortex Cloud tenant for which you are permissioned to create, modify and delete resources:
- `CORTEX_API_URL`
- `CORTEX_API_KEY`
- `CORTEX_API_KEY_ID`

### Additional Tools

The following tools are not necessary for contributing to the provider. They are largely used within the CI workflow to handle miscellanious tasks. However, if you would like to do us a solid and ensure that your pull request will pass the CI checks, feel free to install them on your local machine and execute them against the project after you've completed your changes to the provider.

- Copywrite v0.22.0
  - `brew tap hashicorp/tap`
  - `brew install hashicorp/tap/copywrite`
- Tfplugindocs v0.21.0
  - `go get github.com/hashicorp/terraform-plugin-docs/cmd/tfplugindocs`

# Debugging with Visual Studio Code

To debug the provider, install the [Go for Visual Studio Code](https://marketplace.visualstudio.com/items?itemName=golang.Go) extension from the marketplace.

After installing the extension, open the project in Visual Studio Code select the `Run and Debug` option on the sidebar and click `create a launch.json file`.

Example `launch.json` definition:

```
{
    "version": "0.2.0",
    "configurations": [
        {
            "name": "Debug Terraform Provider",
            "type": "go",
            "request": "launch",
            "mode": "debug",
            // this assumes your workspace is the root of the repo
            "program": "${workspaceFolder}",
            "env": {},
            "args": [
                "-debug=true"
            ],
        }
    ]
}
```
