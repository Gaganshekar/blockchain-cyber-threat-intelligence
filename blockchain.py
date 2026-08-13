import hashlib
import json
import time
from dataclasses import dataclass, asdict



@dataclass
class Block:
    index: int
    timestamp: str
    data: dict
    previous_hash: str
    nonce: int
    hash: str


class Blockchain:

    def __init__(self, difficulty=4):
        self.chain = []
        self.difficulty = difficulty
        self.create_genesis_block()

    # ----------------------------
    # Create Genesis Block
    # ----------------------------
    def create_genesis_block(self):

        genesis = Block(
            index=0,
            timestamp=time.strftime("%Y-%m-%d %H:%M:%S"),
            data={
                "message": "Genesis Block"
            },
            previous_hash="0",
            nonce=0,
            hash=""
        )

        genesis.hash = self.calculate_hash(genesis)

        self.chain.append(genesis)

    # ----------------------------
    # Get Last Block
    # ----------------------------
    def get_latest_block(self):
        return self.chain[-1]

    # ----------------------------
    # Calculate Hash
    # ----------------------------
    def calculate_hash(self, block):

        block_string = json.dumps(
            {
                "index": block.index,
                "timestamp": block.timestamp,
                "data": block.data,
                "previous_hash": block.previous_hash,
                "nonce": block.nonce
            },
            sort_keys=True
        ).encode()

        return hashlib.sha256(block_string).hexdigest()

    # ----------------------------
    # Proof of Work
    # ----------------------------
    def proof_of_work(self, block):

        block.nonce = 0

        computed_hash = self.calculate_hash(block)

        while not computed_hash.startswith("0" * self.difficulty):

            block.nonce += 1

            computed_hash = self.calculate_hash(block)

        return computed_hash

    # ----------------------------
    # Add New Block
    # ----------------------------
    # ----------------------------
    # Add New Block
    # ----------------------------
    def add_block(self, threat_data):

        previous = self.get_latest_block()

        block = Block(

            index=previous.index + 1,

            timestamp=time.strftime("%Y-%m-%d %H:%M:%S"),

            data=threat_data,

            previous_hash=previous.hash,

            nonce=0,

            hash=""

        )

        # Mine block
        block.hash = self.proof_of_work(block)

        # Add block to blockchain
        self.chain.append(block)

        return block
    # ----------------------------
    # Verify Blockchain
    # ----------------------------
    def is_chain_valid(self):

        for i in range(1, len(self.chain)):

            current = self.chain[i]

            previous = self.chain[i - 1]

            # Verify current hash
            if current.hash != self.calculate_hash(current):
                return False

            # Verify previous hash
            if current.previous_hash != previous.hash:
                return False

            # Verify Proof of Work
            if not current.hash.startswith("0" * self.difficulty):
                return False

        return True

    # ----------------------------
    # Display Chain
    # ----------------------------
    def display_chain(self):

        chain = []

        for block in self.chain:

            chain.append(
                asdict(block)
            )

        return chain

    # ----------------------------
    # Get Chain
    # ----------------------------
    def get_chain(self):

        return self.display_chain()

    # ----------------------------
    # Total Blocks
    # ----------------------------
    def total_blocks(self):

        return len(self.chain)

    # ----------------------------
    # Blockchain Statistics
    # ----------------------------
    def get_statistics(self):

        return {
            "total_blocks": len(self.chain),
            "difficulty": self.difficulty,
            "valid": self.is_chain_valid()
        }

    # ----------------------------
    # Get Latest Hash
    # ----------------------------
    def get_latest_hash(self):

        return self.get_latest_block().hash

    # ----------------------------
    # Export Blockchain
    # ----------------------------
    def export_json(self):

        return json.dumps(
            self.display_chain(),
            indent=4
        )

    # ----------------------------
    # Verify Single Block
    # ----------------------------
    def verify_block(self, index):

        if index >= len(self.chain):

            return False

        block = self.chain[index]

        calculated = self.calculate_hash(block)

        return calculated == block.hash

    # ----------------------------
    # Blockchain Information
    # ----------------------------
    def blockchain_info(self):

        return {

            "Blocks": len(self.chain),

            "Difficulty": self.difficulty,

            "Valid": self.is_chain_valid(),

            "Latest Hash": self.get_latest_hash()

        }