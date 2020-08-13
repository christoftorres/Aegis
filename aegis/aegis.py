#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import time
import http
import json
import random
import requests
import argparse
import traceback
import settings

from web3 import Web3
from utils import *
from rosetta import *
from dynamic_call_tree import *
from control_flow_graph import *
from dynamic_taint_analysis import *

def analyze_trace(model, trace, step, transaction, taint_runner, call_tree, control_flow_graph, dependencies):
    execution_begin = time.time()

    if settings.RESULTS_FOLDER:
        result = {}
        result["transaction"] = transaction["hash"]
        result["block"] = transaction["blockNumber"]
        result["patterns"] = []

    first_step = step
    while step in trace:
        if settings.DEBUG_MODE:
            if step == first_step:
                print("")
                print("Analyzing transaction: "+transaction["hash"]+" (block: "+str(transaction["blockNumber"])+")")
                print(transaction["from"].lower()+" --> "+transaction["to"].lower())
                print("")
                print("Step \t PC \t Operation\t Gas       \t GasCost \t Depth")
                print("---------------------------------------------------------------------------")
            print(str(step)+" \t "+str(trace[step]["pc"])+" \t "+trace[step]["op"].ljust(10)+"\t "+str(trace[step]["gas"]).ljust(10)+" \t "+str(trace[step]["gasCost"]).ljust(10)+" \t "+str(trace[step]["depth"])+" \t "+str(control_flow_graph.current_contract_address)+(" \t "+"[Error]" if "error" in trace[step] else ""))

        control_flow_graph.execute(trace, step, transaction)
        taint_runner.propagate_taint(trace[step], control_flow_graph.current_contract_address)
        call_tree.execute(trace, step)


        if "patterns" in dir(model):
            for pattern in model.patterns:
                try:
                    if evaluate_pattern(pattern.condition, trace, step, taint_runner, call_tree, control_flow_graph, dependencies):
                        condition = pattern_to_str(pattern.condition, trace, step, control_flow_graph, dependencies)
                        print("=================================== Warning =======================================")
                        print("Transaction: \t "+transaction["hash"])
                        print("Contract: \t "+control_flow_graph.current_contract_address)
                        print("Description: \t "+pattern.description)
                        if settings.DEBUG_MODE:
                            print("Condition: "+condition)
                        print("===================================================================================")
                        if settings.RESULTS_FOLDER:
                            detected_pattern = {}
                            detected_pattern["description"] = pattern.description
                            detected_pattern["condition"] = condition
                            detected_pattern["contract"] = control_flow_graph.current_contract_address
                            result["patterns"].append(detected_pattern)
                except Exception as e:
                    if not "error" in trace[step]:
                            raise e
        step += 1

    execution_end = time.time()
    execution_delta = execution_end - execution_begin

    print("Analyzing transaction "+str(transaction["hash"])+" took %.2f second(s)." % execution_delta)

    if settings.DEBUG_MODE:
        print("---------------------------------------------------------------------------")
        print("Execution took %.2f second(s)." % execution_delta)

    if settings.RESULTS_FOLDER:
        result["execution_time"] = execution_delta

    if settings.SAVE_CFG:
        control_flow_graph.save_control_flow_graph(transaction["hash"], settings.SAVE_CFG)

    if settings.RESULTS_FOLDER:
        return (step, dependencies, result)

    return (step, dependencies, None)

def analyze_transactions(connection, transactions):
    results = []

    if not transactions:
        return results

    model = load_model(settings.PATTERNS_FILE)
    if not model:
        return results

    if args.save:
        execution_trace["transactions"] = transactions

    bins = []
    for transaction in transactions:
        found = False
        for i in range(len(bins)):
            for j in range(len(bins[i])):
                if bins[i][j]["blockNumber"] == transaction["blockNumber"] and bins[i][j]["from"] != transaction["from"]:
                    bins[i].append(transaction)
                    found = True
                    break
                if bins[i][j]["from"] == transaction["from"] and bins[i][j]["input"] != transaction["input"]:
                    bins[i].append(transaction)
                    found = True
                    break
            if found:
                break
        if not found:
            bins.append([transaction])

    transaction_counter = 0

    for i in range(len(bins)):
        step = 0
        trace = {}
        dependencies = {}

        taint_runner = TaintRunner()
        call_tree = DynamicCallTree()
        control_flow_graph = ControlFlowGraph()

        for j in range(len(bins[i])):
            transaction = bins[i][j]
            transaction_counter += 1

            dependency_steps = set()
            for pattern in list(dependencies):
                if not pattern.__class__.__name__ == "DataDependency" and dependencies[pattern]["dependencies"]:
                    dependencies[pattern]["sources"] = []
                    dependencies[pattern]["destinations"] = []
                    for k in range(len(dependencies[pattern]["dependencies"])):
                        if not dependencies[pattern]["dependencies"][k]["source"] in dependencies[pattern]["sources"]:
                            dependencies[pattern]["sources"].append(dependencies[pattern]["dependencies"][k]["source"])
                        if not dependencies[pattern]["dependencies"][k]["destination"] in dependencies[pattern]["destinations"]:
                            dependencies[pattern]["destinations"].append(dependencies[pattern]["dependencies"][k]["destination"])
                elif not pattern.__class__.__name__ == "DataDependency":
                    del dependencies[pattern]
                if pattern in dependencies:
                    dependency_steps = dependency_steps.union(set(dependencies[pattern]["sources"]))
                    dependency_steps = dependency_steps.union(set(dependencies[pattern]["destinations"]))
            for t in list(trace):
                if not t in dependency_steps:
                    del trace[t]

            if args.load:
                for k in range(len(execution_trace["traces"][transaction["hash"]]["structLogs"])):
                    trace[k+step] = execution_trace["traces"][transaction["hash"]]["structLogs"][k]
                    trace[k+step]["transaction"] = transaction
            else:
                retrieval_begin = time.time()
                trace_response = request_debug_trace(connection, transaction["hash"])
                if "error" in trace_response:
                    print("An error occured in retrieving the trace: "+str(trace_response["error"]))
                    raise Exception("An error occured in retrieving the trace: {}".format(trace_response["error"]))
                else:
                    if args.save:
                        if not "traces" in execution_trace:
                            execution_trace["traces"] = {}
                        execution_trace["traces"][transaction["hash"]] = trace_response["result"]
                    for k in range(len(trace_response["result"]["structLogs"])):
                        trace[k+step] = trace_response["result"]["structLogs"][k]
                        trace[k+step]["transaction"] = transaction
                retrieval_end = time.time()
                retrieval_delta = retrieval_end - retrieval_begin
                print("Retrieving transaction "+transaction["hash"]+" took %.2f second(s). (%d MB) (%d/%d)" % (retrieval_delta, (deep_getsizeof(trace, set()) / 1024) / 1024, transaction_counter, len(transactions)))

            for pattern in list(dependencies):
                if dependencies[pattern]["dependencies"]:
                    del dependencies[pattern]

            step, dependencies, result = analyze_trace(model, trace, step, transaction, taint_runner, call_tree, control_flow_graph, dependencies)

            taint_runner.clear_taint()

            if settings.RESULTS_FOLDER:
                results.append(result)

    return results

def main():
    execution_begin = time.time()
    connection = None

    try:
        global args

        print('')
        print('       d8888 8888888888 .d8888b.  8888888 .d8888b. ')
        print('      d88888 888       d88P  Y88b   888  d88P  Y88b')
        print('     d88P888 888       888    888   888  Y88b.     ')
        print('    d88P 888 8888888   888          888   "Y888b.  ')
        print('   d88P  888 888       888  88888   888      "Y88b.')
        print('  d88P   888 888       888    888   888        "888')
        print(' d8888888888 888       Y88b  d88P   888  Y88b  d88P')
        print('d88P     888 8888888888 "Y8888P88 8888888 "Y8888P" ')
        print('')

        parser = argparse.ArgumentParser()

        group_1 = parser.add_mutually_exclusive_group(required=True)
        group_1.add_argument(
            "-t", "--transaction", type=str, help="transaction hash to be analyzed")
        group_1.add_argument(
            "-b", "--block", type=int, help="block number to be analyzed")
        group_1.add_argument(
            "-c", "--contract", type=str, help="contract address to be analyzed")

        group_2 = parser.add_mutually_exclusive_group(required=False)
        group_2.add_argument(
            "-l", "--load", type=str, help="load execution information from file")
        group_2.add_argument(
            "-s", "--save", type=str, help="save execution information to file")

        parser.add_argument(
            "-p", "--patterns", type=str, help="file containing patterns to be analyzed (default: '"+settings.PATTERNS_FILE+"')")
        parser.add_argument(
            "-r", "--results", type=str, help="folder where results should be stored")
        parser.add_argument(
            "--cfg", type=str, help="save control flow graph to a file")
        parser.add_argument(
            "--debug", action="store_true", help="print debug information to the console")
        parser.add_argument(
            "--host", type=str, help="HTTP-RPC server listening interface (default: '"+settings.RPC_HOST+"')")
        parser.add_argument(
            "--port", type=int, help="HTTP-RPC server listening port (default: '"+str(settings.RPC_PORT)+"')")
        parser.add_argument(
            "-v", "--version", action="version", version="AEGIS version 0.0.1 - 'Apollo'")

        args = parser.parse_args()

        if args.debug:
            settings.DEBUG_MODE = args.debug

        if args.patterns:
            settings.PATTERNS_FILE = args.patterns
        else:
            settings.PATTERNS_FILE = os.path.join(os.path.dirname(os.path.realpath(__file__)), settings.PATTERNS_FILE)
            
        if args.host:
            settings.RPC_HOST = args.host

        if args.port:
            settings.RPC_PORT = args.port

        network = ""

        tries = 0
        while not (settings.W3 and connection) and tries < 10:
            try:
                tries += 1
                if not args.load:
                    settings.W3 = Web3(Web3.HTTPProvider("http://"+settings.RPC_HOST+":"+str(settings.RPC_PORT)))
                    if settings.W3.isConnected():
                        network = ""
                        if settings.W3.net.version   == "1":
                            network = "mainnet"
                        elif settings.W3.net.version == "2":
                            network = "morden"
                        elif settings.W3.net.version == "3":
                            network = "ropsten"
                        else:
                            network = "unknown"
                        print("Connected to "+str(settings.W3.version.node)+" ("+network+")")
                    else:
                        print("Error: Could not connect to Ethereum client. Please make sure the client is running and settings are correct.")
                    if not settings.W3.eth.syncing:
                        print("Blockchain is in sync (latest block: "+str(settings.W3.eth.blockNumber)+").")
                        print("")
                    else:
                        print("Blockchain is syncing... (synced at %.2f%% - latest block: %d)" % (settings.W3.eth.syncing.currentBlock/settings.W3.eth.syncing.highestBlock*100.0, settings.W3.eth.syncing.currentBlock))
                        print("")
                    connection = http.client.HTTPConnection(settings.RPC_HOST, settings.RPC_PORT)
            except Exception as e:
                if tries < 10:
                    print("Retrying to connect to http://"+settings.RPC_HOST+":"+str(settings.RPC_PORT))
                    time.sleep(30)
                else:
                    print(e)
                    return

        if args.results:
            settings.RESULTS_FOLDER = args.results

        if args.cfg:
            settings.SAVE_CFG = args.cfg

        if args.load or args.save:
            global execution_trace

        if args.load:
            with open(args.load) as file:
                execution_trace = json.load(file)

        if args.save:
            execution_trace = {"transactions": [], "traces": {}}

        if args.transaction:
            if not os.path.isfile(settings.RESULTS_FOLDER+'/'+args.transaction+'.json'):
                transactions = []
                if args.load:
                    transactions = execution_trace["transactions"]
                else:
                    try:
                        transaction = format_transaction(settings.W3.eth.getTransaction(args.transaction))
                        if transaction["to"] and transaction["gas"] > 21000:
                            transactions.append(transaction)
                    except Exception as e:
                        print("Error: Blockchain is not in sync with transaction: "+args.transaction)
                results = analyze_transactions(connection, transactions)
                if settings.RESULTS_FOLDER:
                    with open(settings.RESULTS_FOLDER+'/'+args.transaction+'.json', 'w') as file:
                        json.dump(results, file)
                if args.save:
                    with open(args.save+'/'+args.transaction+'.trace', 'w') as file:
                        json.dump(execution_trace, file)

        if args.block:
            if not os.path.isfile(settings.RESULTS_FOLDER+'/'+str(args.block)+'.json'):
                transactions = []
                if args.load:
                    transactions = execution_trace["transactions"]
                else:
                    try:
                        block = settings.W3.eth.getBlock(args.block)
                        for i in block["transactions"]:
                            transaction = format_transaction(settings.W3.eth.getTransaction(i))
                            if transaction["to"] and transaction["gas"] > 21000:
                                transactions.append(transaction)
                    except:
                        print("Error: Blockchain is not in sync with block number: "+args.block[0])
                print("Analyzing block "+str(args.block)+" with "+str(len(transactions))+" transaction(s).\n")
                results = analyze_transactions(connection, transactions)
                if settings.RESULTS_FOLDER:
                    with open(settings.RESULTS_FOLDER+'/'+str(args.block)+'.json', 'w') as file:
                        json.dump(results, file)
                if args.save:
                    with open(args.save+'/'+str(args.block)+'.trace', 'w') as file:
                        json.dump(execution_trace, file)

        if args.contract:
            if not os.path.isfile(settings.RESULTS_FOLDER+'/'+args.contract+'.json'):
                transactions = []
                if args.load:
                    transactions = execution_trace["transactions"]
                else:
                    api_network = "api" if network == "mainnet" else "api-"+network
                    tries = 0
                    while tries < 10:
                        try:
                            tries += 1
                            etherscan_api_token = random.choice(settings.ETHERSCAN_API_TOKENS)
                            api_response = requests.get("https://"+api_network+".etherscan.io/api?module=account&action=txlist&address="+args.contract+"&startblock=0&endblock="+str(settings.MAX_BLOCK_HEIGHT)+"&sort=asc&apikey="+etherscan_api_token).json()
                            #print("https://"+api_network+".etherscan.io/api?module=account&action=txlist&address="+args.contract+"&startblock=0&endblock="+str(settings.MAX_BLOCK_HEIGHT)+"&sort=asc&apikey="+etherscan_api_token)
                            #print("https://"+api_network+".etherscan.io/api?module=account&action=txlistinternal&address="+args.contract+"&startblock=0&endblock="+str(settings.MAX_BLOCK_HEIGHT)+"&sort=asc&apikey="+etherscan_api_token)
                            if not api_response or "error" in api_response or not "result" in api_response:
                                if "error" in api_response:
                                    print("An error occured in retrieving the list of transactions: "+str(api_response["error"]))
                                else:
                                    print("An unknown error ocurred in retrieving the list of transactions!")
                            else:
                                for transaction in api_response["result"]:
                                    if transaction["to"] and int(transaction["gasUsed"]) > 21000:
                                        if not is_block_within_ranges(int(transaction["blockNumber"]), settings.DOS_ATTACK_BLOCK_RANGES):
                                            if not transaction in transactions:
                                                transactions.append(transaction)
                                break
                        except Exception as e:
                            if tries < 10:
                                print("Retrying to retrieve the list of transactions from etherscan in 1 min.")
                                time.sleep(60)
                            else:
                                raise(e)
                    """# Get the list of "normal" transactions for the given contract address
                    page = 1
                    while True:
                        api_response = requests.get("https://"+api_network+".etherscan.io/api?module=account&action=txlist&address="+args.contract+"&startblock=0&endblock="+str(settings.MAX_BLOCK_HEIGHT)+"&page="+str(page)+"&offset=10000&sort=asc&apikey="+etherscan_api_token).json()
                        if not api_response or "error" in api_response:
                            if "error" in api_response:
                                print("An error occured in retrieving the list of transactions: "+str(api_response["error"]))
                            else:
                                print("An unknown error ocurred in retrieving the list of transactions!")
                        elif "result" in api_response:
                            if not api_response["result"] or len(api_response["result"]) == 0:
                                break
                            else:
                                page += 1
                                for result in api_response["result"]:
                                    transaction = format_transaction(settings.W3.eth.getTransaction(result["hash"]))
                                    if transaction["to"] and transaction["gas"] > 21000:
                                        if not is_block_within_ranges(transaction["blockNumber"], settings.DOS_ATTACK_BLOCK_RANGES):
                                            if not transaction in transactions:
                                                transactions.append(transaction)
                        else:
                            break
                    # Get the list of "internal" transactions for the given contract address
                    page = 1
                    while True:
                        api_response = requests.get("https://"+api_network+".etherscan.io/api?module=account&action=txlistinternal&address="+args.contract+"&startblock=0&endblock="+str(settings.MAX_BLOCK_HEIGHT)+"&page="+str(page)+"&offset=10000&sort=asc&apikey="+etherscan_api_token).json()
                        if not api_response or "error" in api_response:
                            if "error" in api_response:
                                print("An error occured in retrieving the list of transactions: "+str(api_response["error"]))
                            else:
                                print("An unknown error ocurred in retrieving the list of transactions!")
                        elif "result" in api_response:
                            if len(api_response["result"]) == 0:
                                break
                            else:
                                page += 1
                                for result in api_response["result"]:
                                    transaction = format_transaction(settings.W3.eth.getTransaction(result["hash"]))
                                    if transaction["to"] and transaction["gas"] > 21000:
                                        if not is_block_within_ranges(transaction["blockNumber"], settings.DOS_ATTACK_BLOCK_RANGES):
                                            if not transaction in transactions:
                                                transactions.append(transaction)
                        else:
                            break
                    # Sort the list of transactions
                    from operator import itemgetter
                    transactions = sorted(transactions, key=itemgetter('blockNumber', 'transactionIndex'))"""
                print("Analyzing contract "+str(args.contract)+" with "+str(len(transactions))+" transaction(s).\n")
                results = analyze_transactions(connection, transactions)
                if settings.RESULTS_FOLDER:
                    with open(settings.RESULTS_FOLDER+'/'+args.contract+'.json', 'w') as file:
                        json.dump(results, file)
                if args.save:
                    with open(args.save+'/'+args.contract+'.trace', 'w') as file:
                        json.dump(execution_trace, file)

    except argparse.ArgumentTypeError as e:
        print(e)
    except Exception:
        traceback.print_exc()
        if args.transaction:
            print("Transaction: "+args.transaction)
        if args.block:
            print("Block: "+str(args.block))
        if args.contract:
            print("Contract: "+args.contract)
    finally:
        if connection:
            connection.close()
            print("Connection closed.")

    execution_end = time.time()
    execution_delta = execution_end - execution_begin
    print("")
    print("Overall execution took %.2f second(s)." % execution_delta)

if __name__ == '__main__':
    main()
