ÆGIS
====

<img src="https://github.com/christoftorres/Aegis/raw/master/aegis-logo.jpg" width="200">

A generic runtime analysis tool to detect and protect against attacks in Ethereum. Our paper can be found [here](https://orbilu.uni.lu/bitstream/10993/42957/1/Aegis_ASIACCS_2020.pdf).

## !! Important Note !!

:warning: **This is a simplified version of ÆGIS! It is not integrated into an Ethereum client! Instead, it runs as a standalone progam and requires a connection to a fully synced Go-Ethereum (Geth) archive node.**

More information on how to run an archive node can be found [here](https://docs.ethhub.io/using-ethereum/running-an-ethereum-node/#archive-nodes).

## Quick Start

A container with the dependencies set up can be found [here](https://hub.docker.com/r/christoftorres/aegis/).

To open the container, install docker and run:

```
docker pull christoftorres/aegis && docker run -i -t christoftorres/aegis
```

To evaluate a transaction inside the container, run:

```
python3 aegis/aegis.py -t 0x0ec3f2488a93839524add10ea229e773f6bc891b4eb4794c3337d4495263790b --host <RPC_HOST> --port <RPC_PORT>
```

and you are done!

## Custom Docker image build

```
docker build -t aegis .
docker run -it aegis:latest
```

## Installation Instructions

Install Python Dependencies

``` shell
cd aegis
pip3 install -r requirements.txt
```

## Running Instructions

Run ```aegis.py``` on a transaction (```-t```), contract (```-c```) or block (```-b```):

``` shell
# Example of a transaction: DAO hack
python3 aegis.py -t 0x0ec3f2488a93839524add10ea229e773f6bc891b4eb4794c3337d4495263790b --host <RPC_HOST> --port <RPC_PORT>
```

``` shell
# Example of a contract: unconditional reentrancy
python3 aegis.py -c 0x4c9cd71d3dd548e9f32581f34795443346d041b8 --host <RPC_HOST> --port <RPC_PORT>
```

Run ```python3 aegis.py -h``` for a complete list of available options.
