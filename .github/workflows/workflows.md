<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2025 Latchfield Technologies http://latchfield.com -->
# Workflow Automation

This document describes the Continuous Integration and Deployment (CI/CD) workflows for Latchfield projects. The workflows automate building, testing, and publishing Python packages to PyPI environments, ensuring code quality and security.

The project implements two primary workflows:

- **ci-build.yml**: Handles code validation, testing, and package building
- **ci-publish.yml**: Manages the release of packages to PyPI environments

## Security Considerations

- All actions are pinned to commit hashes to prevent supply chain attacks. Dependabot is used to keep these actions up to date.

## Build Workflow

### Requirements
- Builds are automatically triggered on pushes to the `main` branch, version tags, and pull requests.
    - Pull requests must not run integration tests to avoid unnecessary costs and security risks.
- Reused by the "publish" workflow, in the event no build cache exists for the commit.
- Builds on the same ref will be cancelled, preventing outdated builds from continuing.
    - Except when reused by the publish workflow
- The cache of build results are commit-centric to avoid rebuilding when publishing.
- Avoid jobs and steps whenever a cache result is present.

### Workflow Jobs

- **Prebuild Checks**: Validates configuration, checks for cached results, and pre-caches the Python environment cache if needed. It will also indicate downstream jobs to skip if a cache is present.
- **Functional Tests**: Runs unit tests, integration tests, and generates test reports.
- **Security Checks**: Identifies security vulnerabilities and outdated dependencies.
- **Static Analysis**: Ensures code quality and standards compliance.
- **Build Package**: Creates distributable packages.

### Notes

- The functional, security, and static analysis jobs are designed to run in parallel to reduce overall execution time. The build job is dependent on the successful completion of the previous jobs.
- Job-level concurrency is configured to avoid cancelling a job if it is already running on the same commit SHA, but instead reuse its cache when completed.

## Publish Workflow

### Requirements
- Only trigger on manual dispatch to ensure controlled releases.
- Require version tags that match the version in `pyproject.toml`.
- Use PyPA's trusted publishing mechanism for signing packages with Sigstore.
- Use caches for build artifacts from other builds (main, tag) on the same commit sha

### Workflow Jobs

- **Prepublish Checks**: Validates configuration, tags, and determines if the build workflow should be run.  
- **Rebuild (Conditional)**: Rebuilds the package if no cached build exists.
- **Publish Packages**: Uploads the built packages to the specified PyPI environment.

### Notes

- As trusted publishing is not available locally, the upload step is configured to skip if the workflow is run locally with Act.

## Running Locally

These workflows are designed to be runnable with [Act](https://github.com/nektos/act) for faster testing of the workflows. A custom docker image is provided for the local runner.

Build the Act runner using:

```bash
docker build . -f ./dockerfiles/actimage.dockerfile -t actimage
```

Act will use this image automatically as configured in the `.actrc` file in the root of the project. To run the build job, use the following command:

```bash
act -j build
```

The Act documentation indicates that an `event.json` file can be used to simulate the event that triggers the workflow. You can also supply this using a file descriptor redirect as shown below:

```bash 
event_data='{"ref": "refs/tags/v1.0.0"}'
act -j debug -e <(echo "$event_data")
```

Secrets can also be passed to the Act runner locally using Doppler:

```bash
doppler login
doppler run --no-read-env -- act -W .github/workflows/ci-build.yml -j tests -s OPENAI_API_KEY
```

Or, if using a preconfigured `DOPPLER_TOKEN` in the environment, simply run:

```bash
doppler run -- act -W .github/workflows/ci-build.yml -j tests -s OPENAI_API_KEY
```

### Notes
- As of Act version `0.2.75`, the `--inputs` flag only populates the `github.event.inputs` context, not the `inputs` context, despite PRs having been merged to support this. As a result, not all jobs will run correctly. Practically speaking, this currently only affects caching flags, as local publishing is not allowed. A workaround is to delete the `action/cache` using `rm -rf ~/.cache/actcache` when you need to clear the cache (such as when testing local changes without committing).

# Dependabot

Dependabot is used automate dependency updates. It is confiured to:

- Create pull requests for updates grouped by major and minor/patch versions
- Apply cooldown periods based on update significance
- Skip Python CI builds for devcontainer and Docker updates

## Monitored Ecosystems

- **DevContainers**: Updates for devcontainer.json configurations
- **GitHub Actions**: Updates for action versions in workflow files
- **Docker**: Updates for base images in Dockerfiles within .devcontainer and dockerfiles directories
- **Python**: Updates for dependencies in pyproject.toml (via pip ecosystem)

## Update Schedule and Grouping

All ecosystems are scheduled for weekly updates with the following grouping strategy:

- **Minor/patch updates** are grouped together to reduce PR volume
- **Security updates** are grouped separately to prioritize them