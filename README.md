# PyBitShred

PyBitShred is a Python reimplementation of [BitShred](https://github.com/dbrumley/bitshred), a tool for large-scale malware similarity analysis and clustering.

This is my semester project of fall 2023 at EURECOM, France. The project is supervised by Antonino Vitale and Prof. Simone Aonzo. We implemented the tool in Python to make it more accessible and easier to use. We also added two new modes to the tool: the "all section" mode and the "raw file" mode.

Check the presentation slides [here](https://docs.google.com/presentation/d/1L-4U6vH8q7YYatx5d8Q5gbiRkpo0UWAFfMVTqlKDWVw/edit?usp=sharing).

## Getting Started

### Installation

```bash
pip install pybitshred
```

### Usage

Use the following command to see the available options:

```bash
pybitshred -h
```

There are three stages in the BitShred pipeline: ***update***, ***compare***, and ***cluster***. The ***update*** stage is used to update the database with new samples. The ***compare*** stage is used to compare the samples in the database. The ***cluster*** stage is used to cluster the samples in the database.

Check the [original paper](https://users.ece.cmu.edu/~dbrumley/pdf/Jang,%20Brumley,%20Venkataraman_2011_BitShred%20Feature%20Hashing%20Malware%20for%20Scalable%20Triage%20and%20Semantic%20Analysis.pdf) for more details.


## Running Original BitShred

@im-overlord04 wrote a `Dockerfile` to run the original BitShred tool in a container. This is useful as a reference to compare the results of the original tool with the results of the reimplemented tool.

```dockerfile
FROM ubuntu:14.04

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install --no-install-recommends -y \
    wget git automake libtool make cmake gcc g++ pkg-config libmagic-dev \
    tar unzip libglib2.0-0 libssl-dev libdb-dev
RUN ld -v
ARG GIT_SSL_NO_VERIFY=1
RUN apt-get install -y automake1.11 binutils-dev

COPY bitshred/bitshred_single_steps bitshred_single_steps
RUN cd bitshred_single_steps/ && ./configure && make

COPY bitshred/bitshred_single bitshred_single
RUN cd bitshred_single/ && ./configure && make

COPY bitshred/bitshred_openmp bitshred_openmp
RUN cd bitshred_openmp/ && make

WORKDIR /
```


### Build

```bash
docker build . -t nino:bitshred
```

### Usage

```bash
docker run --rm --volume <input_folder>:/input:ro --volume <output_folder>:/db --entrypoint <entrypoint>/src/bitshred nino:bitshred <options>
```

- input_folder: folder containing the samples
- output_folder: folder where the results of the tool will be placed in
- entrypoint: version of the tool to run: only supported either `bitshred_single` or `bitshred_single_steps` or `bitshred_openmp`
- options: command line options required by the tool, specified between double quotes. NB: if you have to specify the input folder, you must use `/input` (any other path is not valid) and it corresponds to the value specified in `input_folder`. Same reasoning for the output folder, whose path to use is `/db`

Example:
```bash
docker run --rm --volume "/home/nino/samples/":/input:ro --volume "/home/nino/output":/db --entrypoint /bitshred_single/src/bitshred nino:bitshred "-b" "/input/" "-t" "0.60"
```
