# HTTP-RPC host
RPC_HOST = 'localhost'
# HTTP-RPC port
RPC_PORT = 8545
# Web3 instance
W3 = None
# Path to patterns file (default 'patterns.rosetta')
PATTERNS_FILE = 'patterns.rosetta'
# Debug mode
DEBUG_MODE = False
# Save CFG to a file
SAVE_CFG = ''
# Folder where results should be saved
RESULTS_FOLDER = ''
# Etherscan API key token
ETHERSCAN_API_TOKENS = [
    'VZ7EMQBT4GNH5F6FBV8FKXAFF6GS4MPKAU'
]
# Maximum block Height
MAX_BLOCK_HEIGHT = 6500000
# Block ranges to skip due to DoS attacks
# https://ethereum.stackexchange.com/questions/9883/why-is-my-node-synchronization-stuck-extremely-slow-at-block-2-306-843/10453
DOS_ATTACK_BLOCK_RANGES = [
    [2283397, 2301372],
    [2283416, 2379641],
    [2421507, 2463130],
    [2468209, 2474792],
    [2550666, 2551428],
    [2619660, 2620384]
]
