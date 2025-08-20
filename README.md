# Zephyr Security Showcase

A practical showcase of security development with Zephyr RTOS, featuring examples, best practices,
and integrations with PSA Crypto, MBEDTLS, and PKCS#11.

This repository provides a small demonstration of our cryptographic development practices at UL.
It includes a subset of PKCS#11 function implementations, built on top of the Zephyr RTOS.

## Project Purpose

This repository serves as a reference and demonstration platform for implementing security features in
embedded systems using Zephyr RTOS. It is designed to support a wide range of use cases—from cryptographic
operations and secure storage to secure communication and testing frameworks.

The goal is to provide developers with examples for reusable components, illustrative examples, and guidance for
building secure applications on Zephyr, regardless of the target hardware or specific security requirements.

## Features

- Integration with NRF SDK and Zephyr RTOS
- Partial implementation of PKCS#11 functions
- Modular and extensible codebase
- Example usage and test cases

## Supported boards

We tested our code on the following boards:

- [nRF7002 DK](https://www.nordicsemi.com/Products/Development-hardware/nRF7002-DK)

Other boards may work but are not actively tested.

### Toolchain setup

To compile the applications, you need the Zephyr SDK installed. For that,
follow the instructions on the [Zephyr SDK installation page](https://docs.zephyrproject.org/latest/develop/toolchains/zephyr_sdk.html)

To be able to flash and work with the nRF7002 DK, you need to set up `nrfutil` first.
Consult the [
`nrfutil` installation page from Nordic](https://docs.nordicsemi.com/bundle/nrfutil/page/guides/installing.html)
for details how to install the `nrfutil` tool.
You may also need to set up `udev` rules.

## Getting Started

This is a very short introduction to what needs to be done to get it running. For more details
or to tackle problems, consult
[Zephyrs 'Getting started' guide](https://docs.zephyrproject.org/latest/develop/getting_started/index.html).

Create a new workspace and change the working directory:

```shell
ul_zephyr_security_showcase_ws
cd ul_zephyr_security_showcase_ws
```

Create and activate a virtual environment:

```shell
python3 -m venv .venv
# This needs to be done in each new shell you open
. .venv/bin/activate
```

Now install `west`, the Zephyr RTOS meta-tool.

```shell
pip install west
```

Initialize the workspace. This will clone this repository and set up all necessary modules as well as Zephyr RTOS:
This may take some time, based on your internet connection.

```shell
west init -m https://github.com/methodpark/zephyr-security-showcase.git
west update
```

Afterward, you can work with the repository and workspace.

## Usage

These list the most common use cases during development.
To cover all use cases, please consult the
[`west` documentation](https://docs.zephyrproject.org/latest/develop/west/index.html).

All commands shall be executed in the workspace `ul_zephyr_security_showcase_ws`.

### Building a sample for a board

```shell
west build -b <board_name> <path_to_application>
# example to build the PKCS11 application for the board with TFM
west build -b nrf7002dk/nrf5340/cpuapp/ns ./zephyr-security-showcase/samples/ul/pkcs11
```

### Flashing to the board

After connecting and building for the board, execute:

```
west flash
```

### Executing tests

Executing (a subset of) tests for all supported boards:

```shell
west twister -T <path_to_test_folder>
# example to execute all unit tests
west twister -T ./zephyr-security-showcase/tests
```
